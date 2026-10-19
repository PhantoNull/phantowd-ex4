//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"slices"
	"strings"
	"unicode/utf8"
)

var errQEMUNFSNetlink = errors.New("NFS fixture kernel observation unavailable")

// Linux6.18.55 Generic Netlink UAPI. This fixture has no mutation encoder or
// name selector: discovering a missing family by name could autoload a module.
func qemuNFSNetlinkRequest(family uint16, command byte, sequence uint32) ([]byte, error) {
	flags, version := uint16(1), byte(1)
	if family == 16 && command == 3 {
		flags, version = 0x301, 2 // complete registered-family dump
	} else if family < 19 || command != 3 && command != 5 && command != 7 {
		return nil, errQEMUNFSNetlink
	}
	if sequence == 0 {
		return nil, errQEMUNFSNetlink
	}
	data := make([]byte, 20)
	binary.NativeEndian.PutUint32(data[:4], uint32(len(data)))
	binary.NativeEndian.PutUint16(data[4:6], family)
	binary.NativeEndian.PutUint16(data[6:8], flags)
	binary.NativeEndian.PutUint32(data[8:12], sequence)
	data[16], data[17] = command, version
	return data, nil
}

type qemuNFSNetlinkReply struct {
	family         uint16
	command        byte
	sequence, port uint32
	done, failed   bool
	bytes          int
	ids            map[uint16]bool
	names          map[string]bool
	nfsFamily      uint16
	payload        []byte
}

func (r *qemuNFSNetlinkReply) refuse() error {
	r.failed, r.nfsFamily, r.payload = true, 0, nil
	return errQEMUNFSNetlink
}

// The transport checks the kernel sender and datagram truncation before this
// private decoder. Refusal is sticky and clears every publishable result.
func (r *qemuNFSNetlinkReply) consume(data []byte) error {
	if _, err := qemuNFSNetlinkRequest(r.family, r.command, r.sequence); err != nil ||
		r.port == 0 || r.done || r.failed || len(data) < 16 || len(data) > 65536 || r.bytes+len(data) > 1<<20 {
		return r.refuse()
	}
	r.bytes += len(data)
	catalog := r.family == 16
	for len(data) > 0 {
		if r.done || len(data) < 16 {
			return r.refuse()
		}
		n := int(binary.NativeEndian.Uint32(data[:4]))
		if n < 16 || n > len(data) || (n+3)&^3 > len(data) {
			return r.refuse()
		}
		kind, flags := binary.NativeEndian.Uint16(data[4:6]), binary.NativeEndian.Uint16(data[6:8])
		wantFlags := uint16(0)
		if catalog {
			wantFlags = 2 // MULTI, not FILTERED/INTR/ACK or mutation flags
		}
		if flags != wantFlags || binary.NativeEndian.Uint32(data[8:12]) != r.sequence || binary.NativeEndian.Uint32(data[12:16]) != r.port {
			return r.refuse()
		}
		body := data[16:n]
		if catalog && kind == 3 {
			if len(body) != 4 || binary.NativeEndian.Uint32(body) != 0 {
				return r.refuse()
			}
			r.done = true
		} else {
			command, version := r.command, byte(1)
			if catalog {
				command, version = 1, 2 // CTRL_CMD_NEWFAMILY
			}
			if kind != r.family || len(body) < 4 || body[0] != command || body[1] != version || body[2] != 0 || body[3] != 0 {
				return r.refuse()
			}
			if catalog {
				id, name, version, header, err := qemuNFSFamilyRecord(body[4:])
				if err != nil || len(r.ids) >= 256 || r.ids[id] || r.names[name] {
					return r.refuse()
				}
				if r.ids == nil {
					r.ids, r.names = make(map[uint16]bool), make(map[string]bool)
				}
				r.ids[id], r.names[name] = true, true
				if name == "nfsd" {
					if id < 19 || version != 1 || header != 0 {
						return r.refuse()
					}
					r.nfsFamily = id
				}
			} else {
				r.payload, r.done = slices.Clone(body[4:]), true
			}
		}
		data = data[(n+3)&^3:]
	}
	return nil
}

func (r *qemuNFSNetlinkReply) result() (uint16, []byte, error) {
	if r.failed || !r.done || r.family == 16 && r.nfsFamily == 0 {
		return 0, nil, errQEMUNFSNetlink
	}
	if r.family == 16 {
		return r.nfsFamily, nil, nil
	}
	return r.family, slices.Clone(r.payload), nil
}

func qemuNFSAttributes(data []byte, visit func(uint16, []byte) error) error {
	if len(data) > 65536 {
		return errQEMUNFSNetlink
	}
	for count := 0; len(data) > 0; count++ {
		if count >= 1024 || len(data) < 4 {
			return errQEMUNFSNetlink
		}
		n := int(binary.NativeEndian.Uint16(data[:2]))
		if n < 4 || n > len(data) || (n+3)&^3 > len(data) {
			return errQEMUNFSNetlink
		}
		if err := visit(binary.NativeEndian.Uint16(data[2:4]), data[4:n]); err != nil {
			return errQEMUNFSNetlink
		}
		data = data[(n+3)&^3:]
	}
	return nil
}

func qemuNFSCString(data []byte, max int) (string, error) {
	if len(data) < 1 || len(data) > max || data[len(data)-1] != 0 || !utf8.Valid(data[:len(data)-1]) || strings.IndexByte(string(data[:len(data)-1]), 0) >= 0 {
		return "", errQEMUNFSNetlink
	}
	return string(data[:len(data)-1]), nil
}

func qemuNFSFamilyRecord(data []byte) (uint16, string, uint32, uint32, error) {
	fields := make(map[uint16][]byte)
	err := qemuNFSAttributes(data, func(kind uint16, value []byte) error {
		base := kind & 0x3fff
		if base < 1 || base > 7 {
			return errQEMUNFSNetlink
		}
		if _, present := fields[base]; present || base <= 5 && kind != base || base > 5 && kind != base && kind != base|0x8000 {
			return errQEMUNFSNetlink
		}
		fields[base] = value
		if base > 5 {
			return qemuNFSFamilyMetadata(base, value)
		}
		return nil
	})
	if err != nil || len(fields[1]) != 2 || len(fields[3]) != 4 || len(fields[4]) != 4 || len(fields[5]) != 4 {
		return 0, "", 0, 0, errQEMUNFSNetlink
	}
	id := binary.NativeEndian.Uint16(fields[1])
	name, err := qemuNFSCString(fields[2], 16)
	if err != nil || id < 16 || name == "" {
		return 0, "", 0, 0, errQEMUNFSNetlink
	}
	return id, name, binary.NativeEndian.Uint32(fields[3]), binary.NativeEndian.Uint32(fields[4]), nil
}

func qemuNFSFamilyMetadata(kind uint16, data []byte) error {
	seen := make(map[uint16]bool)
	return qemuNFSAttributes(data, func(record uint16, value []byte) error {
		index := record & 0x3fff
		if index == 0 || record&0x4000 != 0 || seen[index] || len(seen) >= 256 {
			return errQEMUNFSNetlink
		}
		seen[index] = true
		fields, err := qemuNFSSingleFields(value, 2)
		if err != nil || len(fields) != 2 || len(fields[2]) != 4 {
			return errQEMUNFSNetlink
		}
		if kind == 6 {
			if len(fields[1]) != 4 {
				return errQEMUNFSNetlink
			}
		} else if name, err := qemuNFSCString(fields[1], 16); err != nil || name == "" {
			return errQEMUNFSNetlink
		}
		return nil
	})
}

func qemuNFSSingleFields(data []byte, max uint16) (map[uint16][]byte, error) {
	fields := make(map[uint16][]byte)
	err := qemuNFSAttributes(data, func(kind uint16, value []byte) error {
		if _, exists := fields[kind]; kind == 0 || kind > max || exists {
			return errQEMUNFSNetlink
		}
		fields[kind] = value
		return nil
	})
	if err != nil {
		return nil, errQEMUNFSNetlink
	}
	return fields, nil
}

// Exact owned disposable-kernel profile, not a general production census or
// liveness/lease. All three inputs come from separate correlated GET replies.
func validateQEMUNFSNetlinkProfile(threads, versions, listeners []byte, running bool) error {
	var total uint64
	var pools int
	metadata := make(map[uint16]bool)
	err := qemuNFSAttributes(threads, func(kind uint16, data []byte) error {
		switch kind {
		case 1:
			if len(data) != 4 || pools >= 256 {
				return errQEMUNFSNetlink
			}
			pools++
			total += uint64(binary.NativeEndian.Uint32(data))
		case 2, 3:
			if len(data) != 4 || metadata[kind] {
				return errQEMUNFSNetlink
			}
			metadata[kind] = true
		case 4:
			if _, err := qemuNFSCString(data, 65); err != nil || metadata[kind] {
				return errQEMUNFSNetlink
			}
			metadata[kind] = true // never return the private server scope
		default:
			return errQEMUNFSNetlink
		}
		return nil
	})
	wantThreads, wantListeners := uint64(0), 0
	if running {
		wantThreads, wantListeners = 2, 1
	}
	if err != nil || pools == 0 || len(metadata) != 3 || total != wantThreads {
		return errQEMUNFSNetlink
	}
	versionCount := 0
	err = qemuNFSAttributes(versions, func(kind uint16, data []byte) error {
		fields, err := qemuNFSSingleFields(data, 3)
		_, enabled := fields[3]
		if err != nil || kind != 0x8001 || versionCount != 0 || len(fields) != 3 || len(fields[1]) != 4 ||
			len(fields[2]) != 4 || !enabled || len(fields[3]) != 0 ||
			binary.NativeEndian.Uint32(fields[1]) != 3 || binary.NativeEndian.Uint32(fields[2]) != 0 {
			return errQEMUNFSNetlink
		}
		versionCount++
		return nil
	})
	if err != nil || versionCount != 1 {
		return errQEMUNFSNetlink
	}
	listenerCount := 0
	err = qemuNFSAttributes(listeners, func(kind uint16, data []byte) error {
		fields, err := qemuNFSSingleFields(data, 2)
		transport, stringErr := qemuNFSCString(fields[2], 16)
		if err != nil || stringErr != nil || kind != 0x8001 || listenerCount >= wantListeners ||
			len(fields) != 2 || transport != "tcp" || len(fields[1]) != 128 {
			return errQEMUNFSNetlink
		}
		address := fields[1]
		// sockaddr_storage includes unused padding; only the AF_INET identity
		// fields have meaning here. IPv6 is not this fixed loopback fixture.
		if binary.NativeEndian.Uint16(address[:2]) != 2 || binary.BigEndian.Uint16(address[2:4]) != 2049 ||
			!bytes.Equal(address[4:8], []byte{127, 0, 0, 1}) {
			return errQEMUNFSNetlink
		}
		listenerCount++
		return nil
	})
	if err != nil || listenerCount != wantListeners {
		return errQEMUNFSNetlink
	}
	return nil
}
