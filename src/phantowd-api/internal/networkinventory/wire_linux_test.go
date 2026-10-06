// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"bytes"
	"encoding/binary"
	"math/rand/v2"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func attr(kind uint16, value []byte) []byte {
	b := make([]byte, align(4+len(value)))
	binary.NativeEndian.PutUint16(b, uint16(4+len(value)))
	binary.NativeEndian.PutUint16(b[2:], kind)
	copy(b[4:], value)
	return b
}
func u32(v uint32) []byte { b := make([]byte, 4); binary.NativeEndian.PutUint32(b, v); return b }
func frame(kind, flags uint16, payload []byte) []byte {
	b := make([]byte, align(16+len(payload)))
	binary.NativeEndian.PutUint32(b, uint32(16+len(payload)))
	binary.NativeEndian.PutUint16(b[4:], kind)
	binary.NativeEndian.PutUint16(b[6:], flags)
	binary.NativeEndian.PutUint32(b[8:], 1)
	binary.NativeEndian.PutUint32(b[12:], 9)
	copy(b[16:], payload)
	return b
}
func linkPayload() []byte {
	b := make([]byte, 16)
	binary.NativeEndian.PutUint16(b[2:], unix.ARPHRD_ETHER)
	binary.NativeEndian.PutUint32(b[4:], 2)
	b = append(b, attr(unix.IFLA_IFNAME, []byte("fixture0\x00"))...)
	b = append(b, attr(unix.IFLA_MTU, u32(1500))...)
	b = append(b, attr(unix.IFLA_ADDRESS, []byte{2, 0, 0, 0, 0, 1})...)
	return b
}
func addressPayload() []byte {
	b := []byte{unix.AF_INET, 16, 128, 0, 2, 0, 0, 0}
	binary.NativeEndian.PutUint32(b[4:], 2)
	b = append(b, attr(unix.IFA_ADDRESS, []byte{192, 0, 2, 1})...)
	b = append(b, attr(unix.IFA_LOCAL, []byte{192, 0, 2, 10})...)
	b = append(b, attr(unix.IFA_FLAGS, u32(128))...)
	return b
}
func TestWireRequiresExactCompleteUninterruptedDump(t *testing.T) {
	data := frame(unix.RTM_NEWLINK, unix.NLM_F_MULTI, linkPayload())
	d := dump{seq: 1, port: 9, kind: unix.RTM_NEWLINK}
	if d.consume(data) != nil || d.done || len(d.links) != 1 {
		t.Fatal("link parse")
	}
	if d.consume(frame(unix.NLMSG_DONE, unix.NLM_F_MULTI, u32(0))) != nil || !d.done {
		t.Fatal("completion parse")
	}
	if d.consume(data) != ErrUnavailable {
		t.Fatal("accepted data after completion")
	}
	for _, bad := range [][]byte{
		frame(unix.NLMSG_DONE, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, u32(0)),
		frame(unix.RTM_NEWLINK, unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR, linkPayload()),
		frame(unix.RTM_NEWLINK, unix.NLM_F_MULTI|unix.NLM_F_DUMP_FILTERED, linkPayload()),
		frame(unix.NLMSG_DONE, unix.NLM_F_MULTI, u32(1)),
		frame(unix.NLMSG_DONE, unix.NLM_F_MULTI, nil),
		frame(unix.NLMSG_ERROR, unix.NLM_F_MULTI, u32(0)),
		frame(unix.RTM_NEWADDR, unix.NLM_F_MULTI, addressPayload()),
		frame(unix.RTM_NEWLINK, 0, linkPayload()),
		append(frame(unix.NLMSG_DONE, unix.NLM_F_MULTI, u32(0)), data...),
		append(bytes.Clone(data), 1), data[:len(data)-1], {}, make([]byte, maxDatagramBytes+1),
	} {
		d := dump{seq: 1, port: 9, kind: unix.RTM_NEWLINK}
		if d.consume(bad) != ErrUnavailable {
			t.Fatal("accepted uncertain dump")
		}
	}
	for _, offset := range []int{0, 8, 12} {
		bad := bytes.Clone(data)
		binary.NativeEndian.PutUint32(bad[offset:], 0xffffffff)
		d := dump{seq: 1, port: 9, kind: unix.RTM_NEWLINK}
		if d.consume(bad) != ErrUnavailable {
			t.Fatal("accepted header mismatch")
		}
	}
	d = dump{seq: 1, port: 9, kind: unix.RTM_NEWLINK, bytes: maxDumpBytes}
	if d.consume(data) != ErrUnavailable {
		t.Fatal("unbounded dump")
	}
	d = dump{seq: 1, port: 9, kind: unix.RTM_NEWLINK, links: make([]link, MaxInterfaces)}
	if d.consume(data) != ErrUnavailable {
		t.Fatal("unbounded links")
	}
}

func TestWirePreservesAddressFlagsAndPointToPointPeer(t *testing.T) {
	a, e := parseAddress(addressPayload())
	if e != nil || a.prefix.String() != "192.0.2.10/16" || a.peer.String() != "192.0.2.1" || a.flags != 128 || a.index != 2 {
		t.Fatal("lost address state/peer")
	}
	bad := addressPayload()
	bad[2] = 0
	if _, e := parseAddress(bad); e != ErrUnavailable {
		t.Fatal("inconsistent address flags")
	}
	bad = addressPayload()
	bad[1] = 33
	if _, e := parseAddress(bad); e != ErrUnavailable {
		t.Fatal("invalid prefix length")
	}
	for _, bad := range [][]byte{nil, {unix.AF_INET}, append(linkPayload(), attr(unix.IFLA_IFNAME, []byte("duplicate\x00"))...), append(linkPayload(), attr(unix.IFLA_MTU|0x8000, u32(1))...)} {
		if _, e := parseLink(bad); e != ErrUnavailable {
			t.Fatal("accepted malformed link")
		}
	}
	for _, bad := range [][]byte{nil, addressPayload()[:9], append(addressPayload(), attr(unix.IFA_ADDRESS, []byte{1, 2, 3, 4})...)} {
		if _, e := parseAddress(bad); e != ErrUnavailable {
			t.Fatal("accepted malformed address")
		}
	}
}

func TestWireIPv6ScopeFullFlagsAndScalarRefusals(t *testing.T) {
	data := []byte{unix.AF_INET6, 64, 64, 253, 0, 0, 0, 0}
	binary.NativeEndian.PutUint32(data[4:], 2)
	value := netip.MustParseAddr("fe80::10").As16()
	data = append(data, attr(unix.IFA_ADDRESS, value[:])...)
	data = append(data, attr(unix.IFA_FLAGS, u32(0x840))...)
	a, e := parseAddress(data)
	if e != nil || a.prefix.String() != "fe80::10/64" || a.peer != a.prefix.Addr() || a.scope != 253 || a.flags != 0x840 {
		t.Fatal("IPv6 address scope/state lost")
	}
	for _, bad := range [][]byte{
		append(data, attr(unix.IFA_LOCAL, []byte{1})...),
		append(data, attr(unix.IFA_FLAGS, u32(0x840))...),
		append(addressPayload()[:8], attr(unix.IFA_ADDRESS, []byte{1})...),
	} {
		if _, e := parseAddress(bad); e != ErrUnavailable {
			t.Fatal("invalid address attribute accepted")
		}
	}
	for _, kind := range []uint16{unix.IFLA_MTU, unix.IFLA_MASTER, unix.IFLA_LINK} {
		bad := append(linkPayload(), attr(kind, []byte{1})...)
		if _, e := parseLink(bad); e != ErrUnavailable {
			t.Fatal("invalid link scalar accepted")
		}
	}
	l, e := parseLink(append(append(linkPayload(), attr(unix.IFLA_MASTER, u32(3))...), attr(unix.IFLA_LINK, u32(4))...))
	if e != nil || l.master != 3 || l.lower != 4 {
		t.Fatal("link topology lost")
	}
	d := dump{seq: 1, port: 9, kind: unix.RTM_NEWADDR, addresses: make([]ipAddress, MaxAddresses)}
	if d.consume(frame(unix.RTM_NEWADDR, unix.NLM_F_MULTI, addressPayload())) != ErrUnavailable {
		t.Fatal("address bound lost")
	}
}

func TestWireBoundedMutationNoPanic(t *testing.T) {
	seed := append(frame(unix.RTM_NEWLINK, unix.NLM_F_MULTI, linkPayload()), frame(unix.NLMSG_DONE, unix.NLM_F_MULTI, u32(0))...)
	rng := rand.New(rand.NewPCG(6102, 20261003))
	for range 5000 {
		data := bytes.Clone(seed)
		for range 1 + rng.IntN(8) {
			data[rng.IntN(len(data))] = byte(rng.IntN(256))
		}
		d := dump{seq: 1, port: 9, kind: unix.RTM_NEWLINK}
		if e := d.consume(data); e != nil && e != ErrUnavailable {
			t.Fatal("non-redacted failure")
		}
	}
}

func FuzzWireConsume(f *testing.F) {
	f.Add(append(frame(unix.RTM_NEWLINK, unix.NLM_F_MULTI, linkPayload()), frame(unix.NLMSG_DONE, unix.NLM_F_MULTI, u32(0))...))
	f.Add(frame(unix.RTM_NEWADDR, unix.NLM_F_MULTI, addressPayload()))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		for _, kind := range []uint16{unix.RTM_NEWLINK, unix.RTM_NEWADDR} {
			d := dump{seq: 1, port: 9, kind: kind}
			if e := d.consume(data); e != nil && e != ErrUnavailable {
				t.Fatal("non-redacted error")
			}
			if len(d.links) > MaxInterfaces || len(d.addresses) > MaxAddresses || d.bytes > maxDumpBytes {
				t.Fatal("unbounded parser state")
			}
		}
	})
}
