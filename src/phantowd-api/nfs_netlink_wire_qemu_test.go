//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/binary"
	"slices"
	"testing"
)

func nfsWireAttribute(kind uint16, value []byte) []byte {
	data := make([]byte, (4+len(value)+3)&^3)
	binary.NativeEndian.PutUint16(data[:2], uint16(4+len(value)))
	binary.NativeEndian.PutUint16(data[2:4], kind)
	copy(data[4:], value)
	return data
}

func nfsWireU32(value uint32) []byte {
	data := make([]byte, 4)
	binary.NativeEndian.PutUint32(data, value)
	return data
}

func nfsWireFrame(kind, flags uint16, sequence, port uint32, body []byte) []byte {
	data := make([]byte, (16+len(body)+3)&^3)
	binary.NativeEndian.PutUint32(data[:4], uint32(16+len(body)))
	binary.NativeEndian.PutUint16(data[4:6], kind)
	binary.NativeEndian.PutUint16(data[6:8], flags)
	binary.NativeEndian.PutUint32(data[8:12], sequence)
	binary.NativeEndian.PutUint32(data[12:16], port)
	copy(data[16:], body)
	return data
}

func nfsWireFamily(id uint16, name string) []byte {
	number := make([]byte, 2)
	binary.NativeEndian.PutUint16(number, id)
	body := []byte{1, 2, 0, 0}
	for _, attr := range [][]byte{nfsWireAttribute(1, number), nfsWireAttribute(2, append([]byte(name), 0)),
		nfsWireAttribute(3, nfsWireU32(1)), nfsWireAttribute(4, nfsWireU32(0)), nfsWireAttribute(5, nfsWireU32(0))} {
		body = append(body, attr...)
	}
	return nfsWireFrame(16, 2, 1, 99, body)
}

func TestQEMUNFSRebootNetlinkCatalogRequiresCompleteCorrelatedDump(t *testing.T) {
	first := nfsWireFamily(42, "nfsd")
	done := nfsWireFrame(3, 2, 1, 99, nfsWireU32(0))
	reply := qemuNFSNetlinkReply{family: 16, command: 3, sequence: 1, port: 99}
	if err := reply.consume(first); err != nil {
		t.Fatal("complete family record refused", err)
	}
	if _, _, err := reply.result(); err == nil {
		t.Fatal("partial catalog published a selected family")
	}
	if err := reply.consume(done); err != nil {
		t.Fatal(err)
	}
	if family, data, err := reply.result(); err != nil || family != 42 || data != nil {
		t.Fatal("complete catalog did not resolve the exact registered family", family, err)
	}
	for _, change := range []func([]byte){
		func(b []byte) { binary.NativeEndian.PutUint32(b[8:12], 2) },
		func(b []byte) { binary.NativeEndian.PutUint32(b[12:16], 98) },
		func(b []byte) { binary.NativeEndian.PutUint16(b[6:8], 0x12) },
		func(b []byte) { b[17] = 1 },
		func(b []byte) { b[18] = 1 },
	} {
		bad := slices.Clone(first)
		change(bad)
		r := qemuNFSNetlinkReply{family: 16, command: 3, sequence: 1, port: 99}
		if r.consume(bad) == nil || r.consume(first) == nil {
			t.Fatal("bad correlation or restored bytes revived the reply")
		}
		if _, data, err := r.result(); err == nil || data != nil {
			t.Fatal("failed dump published a partial result")
		}
	}
}

func TestQEMUNFSRebootNetlinkCatalogRejectsAmbiguousAndMalformedMetadata(t *testing.T) {
	first := nfsWireFamily(42, "nfsd")
	done := nfsWireFrame(3, 2, 1, 99, nfsWireU32(0))
	body := append(slices.Clone(first[16:]), nfsWireAttribute(6, []byte{1, 2, 3})...)
	malformedMetadata := nfsWireFrame(16, 2, 1, 99, body)
	for _, frames := range [][][]byte{{first, first}, {first, nfsWireFamily(43, "nfsd")},
		{first, nfsWireFamily(42, "unrelated")}, {malformedMetadata}} {
		r := qemuNFSNetlinkReply{family: 16, command: 3, sequence: 1, port: 99}
		for _, frame := range frames {
			_ = r.consume(frame)
		}
		_ = r.consume(done)
		if _, data, err := r.result(); err == nil || data != nil {
			t.Fatal("ambiguous/incomplete family metadata published a selected family")
		}
	}
}

func TestQEMUNFSRebootNetlinkRequestsAreFixedGETs(t *testing.T) {
	for _, command := range []byte{3, 5, 7} {
		request, err := qemuNFSNetlinkRequest(42, command, 7)
		if err != nil || len(request) != 20 || binary.NativeEndian.Uint16(request[6:8]) != 1 ||
			binary.NativeEndian.Uint16(request[4:6]) != 42 || binary.NativeEndian.Uint32(request[8:12]) != 7 ||
			binary.NativeEndian.Uint32(request[12:16]) != 0 || request[16] != command || request[17] != 1 || request[18] != 0 || request[19] != 0 {
			t.Fatal("GET request contains selectors, wrong identity or mutation flags", err)
		}
	}
	catalog, err := qemuNFSNetlinkRequest(16, 3, 1)
	if err != nil || len(catalog) != 20 || binary.NativeEndian.Uint16(catalog[6:8]) != 0x301 || catalog[17] != 2 {
		t.Fatal("family discovery must be a complete attribute-free dump, never named lookup", err)
	}
	for _, family := range []uint16{0, 15, 16, 17, 18, 42} {
		for command := byte(0); command < 12; command++ {
			allowed := family == 16 && command == 3 || family >= 19 && (command == 3 || command == 5 || command == 7)
			request, err := qemuNFSNetlinkRequest(family, command, 1)
			if allowed != (err == nil) || !allowed && request != nil {
				t.Fatal("request allowlist accepts a mutation or invalid family", family, command)
			}
		}
	}
	if data, err := qemuNFSNetlinkRequest(42, 3, 0); err == nil || data != nil {
		t.Fatal("zero correlation sequence accepted")
	}
}

func nfsWireProfile(threads ...uint32) (threadData, versions, listeners []byte) {
	for _, value := range threads {
		threadData = append(threadData, nfsWireAttribute(1, nfsWireU32(value))...)
	}
	for _, attr := range [][]byte{nfsWireAttribute(2, nfsWireU32(90)), nfsWireAttribute(3, nfsWireU32(90)), nfsWireAttribute(4, []byte("private-scope\x00"))} {
		threadData = append(threadData, attr...)
	}
	version := append(nfsWireAttribute(1, nfsWireU32(3)), nfsWireAttribute(2, nfsWireU32(0))...)
	version = append(version, nfsWireAttribute(3, nil)...)
	versions = nfsWireAttribute(0x8001, version)
	address := make([]byte, 128)
	binary.NativeEndian.PutUint16(address[:2], 2)
	binary.BigEndian.PutUint16(address[2:4], 2049)
	copy(address[4:8], []byte{127, 0, 0, 1})
	listener := append(nfsWireAttribute(2, []byte("tcp\x00")), nfsWireAttribute(1, address)...)
	listeners = nfsWireAttribute(0x8001, listener)
	return
}

func TestQEMUNFSRebootNetlinkProfileRequiresExactListenerIdentity(t *testing.T) {
	for _, pools := range [][]uint32{{2}, {1, 1}, {0, 2}} {
		threads, versions, listeners := nfsWireProfile(pools...)
		if err := validateQEMUNFSNetlinkProfile(threads, versions, listeners, true); err != nil {
			t.Fatal("valid owned-loopback profile or legitimate pool repetition refused", err)
		}
		for _, mutate := range []func([]byte){
			func(b []byte) { b[16] = 0 }, // sockaddr follows outer/transport/address headers
			func(b []byte) { b[18] = 0 },
			func(b []byte) { b[20] = 0 },
			func(b []byte) { b[23] = 2 },
		} {
			bad := slices.Clone(listeners)
			mutate(bad)
			if validateQEMUNFSNetlinkProfile(threads, versions, bad, true) == nil {
				t.Fatal("wrong family, port or source address admitted")
			}
		}
	}
	threads, versions, listeners := nfsWireProfile(0)
	if validateQEMUNFSNetlinkProfile(threads, versions, nil, false) != nil || validateQEMUNFSNetlinkProfile(threads, versions, listeners, false) == nil {
		t.Fatal("zero threads confused with no listeners")
	}
}

func TestQEMUNFSRebootNetlinkRefusesPartialUnknownOrBroadenedProfiles(t *testing.T) {
	threads, versions, listeners := nfsWireProfile(2)
	for field, original := range [][]byte{threads, versions, listeners} {
		for cut := 0; cut < len(original); cut++ {
			parts := [][]byte{threads, versions, listeners}
			parts[field] = original[:cut]
			if validateQEMUNFSNetlinkProfile(parts[0], parts[1], parts[2], true) == nil {
				t.Fatal("partial profile accepted", field, cut)
			}
		}
		for _, suffix := range [][]byte{{0}, nfsWireAttribute(99, nil), original} {
			parts := [][]byte{threads, versions, listeners}
			parts[field] = append(slices.Clone(original), suffix...)
			if validateQEMUNFSNetlinkProfile(parts[0], parts[1], parts[2], true) == nil {
				t.Fatal("unknown or duplicate profile accepted", field)
			}
		}
	}
	for _, pools := range [][]uint32{{}, {1}, {3}, {^uint32(0), ^uint32(0)}, make([]uint32, 257)} {
		bad, _, _ := nfsWireProfile(pools...)
		if validateQEMUNFSNetlinkProfile(bad, versions, listeners, true) == nil {
			t.Fatal("missing, excessive or overflow-shaped pool count accepted")
		}
	}
	maximumPools := make([]uint32, 256)
	maximumPools[255] = 2
	bounded, _, _ := nfsWireProfile(maximumPools...)
	if validateQEMUNFSNetlinkProfile(bounded, versions, listeners, true) != nil {
		t.Fatal("inclusive pool limit refused")
	}
	for _, change := range []func([]byte){
		func(b []byte) { b[8] = 4 },  // major version
		func(b []byte) { b[16] = 1 }, // minor version
		func(b []byte) { b[3] = 0 },  // missing nested flag
	} {
		bad := slices.Clone(versions)
		change(bad)
		if validateQEMUNFSNetlinkProfile(threads, bad, listeners, true) == nil {
			t.Fatal("broadened or unqualified protocol accepted")
		}
	}
	for _, change := range []func([]byte){
		func(b []byte) { copy(b[8:12], []byte("udp\x00")) },
		func(b []byte) { b[16] = 10 }, // AF_INET6 is not this fixture
		func(b []byte) { b[3] = 0 },
	} {
		bad := slices.Clone(listeners)
		change(bad)
		if validateQEMUNFSNetlinkProfile(threads, versions, bad, true) == nil {
			t.Fatal("wrong transport or unqualified address family accepted")
		}
	}
}

func TestQEMUNFSRebootNetlinkFramingNeverPublishesFailedReplies(t *testing.T) {
	body := append([]byte{3, 1, 0, 0}, nfsWireAttribute(1, nfsWireU32(2))...)
	valid := nfsWireFrame(42, 0, 7, 99, body)
	for cut := 0; cut < len(valid); cut++ {
		r := qemuNFSNetlinkReply{family: 42, command: 3, sequence: 7, port: 99}
		if r.consume(valid[:cut]) == nil {
			t.Fatal("truncated complete datagram accepted", cut)
		}
		if _, data, err := r.result(); err == nil || data != nil {
			t.Fatal("failed datagram published bytes")
		}
	}
	for _, data := range [][]byte{append(slices.Clone(valid), 0), append(slices.Clone(valid), valid...),
		nfsWireFrame(2, 0, 7, 99, nfsWireU32(0)), make([]byte, 65537)} {
		r := qemuNFSNetlinkReply{family: 42, command: 3, sequence: 7, port: 99}
		if r.consume(data) == nil || r.consume(valid) == nil {
			t.Fatal("unknown, duplicate, excessive or restored reply accepted")
		}
	}
	r := qemuNFSNetlinkReply{family: 42, command: 3, sequence: 7, port: 99}
	if r.consume(valid) != nil {
		t.Fatal("valid complete getter reply refused")
	}
	_, got, err := r.result()
	if err != nil || !slices.Equal(got, body[4:]) {
		t.Fatal("complete getter result unavailable", err)
	}
	got[0] ^= 1
	_, again, _ := r.result()
	if slices.Equal(got, again) {
		t.Fatal("published bytes alias the decoder's retained reply")
	}
}
