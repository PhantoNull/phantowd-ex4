//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"
)

func pendingTCPWireFixtureQEMU() []byte {
	data := make([]byte, 72)
	data[0], data[1] = unix.AF_INET, 1 // TCP_ESTABLISHED
	binary.BigEndian.PutUint16(data[4:6], 30001)
	binary.BigEndian.PutUint16(data[6:8], 1445)
	copy(data[8:12], []byte{127, 0, 0, 1})
	copy(data[24:28], []byte{127, 0, 0, 1})
	binary.NativeEndian.PutUint32(data[40:44], 7)
	binary.NativeEndian.PutUint32(data[44:48], 0x11223344)
	binary.NativeEndian.PutUint32(data[48:52], 0x55667788)
	binary.NativeEndian.PutUint32(data[64:68], 65534)
	binary.NativeEndian.PutUint32(data[68:72], 12345)
	return data
}

func TestPendingTCPWireRefusesIncompleteIdentity(t *testing.T) {
	for name, change := range map[string]func([]byte) []byte{
		"short":             func(b []byte) []byte { return b[:71] },
		"ipv6":              func(b []byte) []byte { b[0] = unix.AF_INET6; return b },
		"listen":            func(b []byte) []byte { b[1] = 10; return b },
		"local-tail":        func(b []byte) []byte { b[12] = 1; return b },
		"peer-tail":         func(b []byte) []byte { b[28] = 1; return b },
		"local-unspecified": func(b []byte) []byte { clear(b[8:12]); return b },
		"peer-unspecified":  func(b []byte) []byte { clear(b[24:28]); return b },
		"zero-local-port":   func(b []byte) []byte { clear(b[4:6]); return b },
		"zero-peer-port":    func(b []byte) []byte { clear(b[6:8]); return b },
		"zero-cookie":       func(b []byte) []byte { clear(b[44:52]); return b },
		"no-cookie": func(b []byte) []byte {
			for i := 44; i < 52; i++ {
				b[i] = 255
			}
			return b
		},
		"zero-inode":            func(b []byte) []byte { clear(b[68:72]); return b },
		"short-attribute":       func(b []byte) []byte { return append(b, 1, 2, 3) },
		"zero-attribute-length": func(b []byte) []byte { return append(b, 0, 0, 0, 0) },
		"attribute-too-short": func(b []byte) []byte {
			attr := make([]byte, 4)
			binary.NativeEndian.PutUint16(attr[:2], 3)
			return append(b, attr...)
		},
		"attribute-missing-padding": func(b []byte) []byte {
			attr := make([]byte, 5)
			binary.NativeEndian.PutUint16(attr[:2], 5)
			return append(b, attr...)
		},
		"oversize": func(b []byte) []byte { return append(b, make([]byte, 4097)...) },
	} {
		t.Run(name, func(t *testing.T) {
			observed, err := parsePendingTCPSocketQEMU(change(pendingTCPWireFixtureQEMU()))
			if !errors.Is(err, ErrUnavailable) || observed != (pendingTCPSocketQEMU{}) {
				t.Fatal("incomplete identity published a socket", err)
			}
		})
	}
}

func TestPendingTCPWireDecodesKernelIPv4Identity(t *testing.T) {
	observed, err := parsePendingTCPSocketQEMU(pendingTCPWireFixtureQEMU())
	if err != nil || observed.local != netip.MustParseAddrPort("127.0.0.1:30001") ||
		observed.peer != netip.MustParseAddrPort("127.0.0.1:1445") ||
		observed.cookie != 0x5566778811223344 || observed.inode != 12345 ||
		observed.uid != 65534 || observed.interfaceID != 7 {
		t.Fatal("kernel identity was not decoded with network/native byte orders", err)
	}
}

func pendingTCPMessageQEMU(kind uint16, payload []byte) []byte {
	data := make([]byte, (16+len(payload)+3)&^3)
	binary.NativeEndian.PutUint32(data[:4], uint32(16+len(payload)))
	binary.NativeEndian.PutUint16(data[4:6], kind)
	binary.NativeEndian.PutUint16(data[6:8], unix.NLM_F_MULTI)
	binary.NativeEndian.PutUint32(data[8:12], 1)
	binary.NativeEndian.PutUint32(data[12:16], 42)
	copy(data[16:], payload)
	return data
}

func TestPendingTCPWireDumpPublishesOnlyCompleteCopiedRows(t *testing.T) {
	dump := &pendingTCPDumpQEMU{seq: 1, port: 42}
	if err := dump.consume(pendingTCPMessageQEMU(unix.SOCK_DIAG_BY_FAMILY, pendingTCPWireFixtureQEMU())); err != nil {
		t.Fatal(err)
	}
	if rows, err := dump.result(); err == nil || rows != nil {
		t.Fatal("unfinished dump published partial rows")
	}
	if err := dump.consume(pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4))); err != nil {
		t.Fatal(err)
	}
	rows, err := dump.result()
	if err != nil || len(rows) != 1 || rows[0].inode != 12345 {
		t.Fatal("completed dump did not publish its identity", err)
	}
	rows[0].inode = 99
	if original, err := dump.result(); err != nil || original[0].inode != 12345 {
		t.Fatal("returned observation aliases the decoder", err)
	}
}

func TestPendingTCPWireDumpRefusesForeignInterruptedAndPartialData(t *testing.T) {
	for name, change := range map[string]func([]byte) []byte{
		"foreign-sequence": func(b []byte) []byte { b[8]++; return b },
		"foreign-port":     func(b []byte) []byte { b[12]++; return b },
		"interrupted": func(b []byte) []byte {
			binary.NativeEndian.PutUint16(b[6:8], unix.NLM_F_MULTI|unix.NLM_F_DUMP_INTR)
			return b
		},
		"not-multipart":    func(b []byte) []byte { clear(b[6:8]); return b },
		"ack":              func(b []byte) []byte { binary.NativeEndian.PutUint16(b[4:6], unix.NLMSG_ERROR); return b },
		"overrun":          func(b []byte) []byte { binary.NativeEndian.PutUint16(b[4:6], unix.NLMSG_OVERRUN); return b },
		"unknown-kind":     func(b []byte) []byte { binary.NativeEndian.PutUint16(b[4:6], 99); return b },
		"short-header":     func(b []byte) []byte { return b[:15] },
		"invalid-length":   func(b []byte) []byte { clear(b[:4]); return b },
		"overflow-length":  func(b []byte) []byte { binary.NativeEndian.PutUint32(b[:4], ^uint32(0)); return b },
		"truncated-length": func(b []byte) []byte { binary.NativeEndian.PutUint32(b[:4], uint32(len(b)+1)); return b },
		"partial-tail":     func(b []byte) []byte { return append(b, 1) },
		"duplicate-row":    func(b []byte) []byte { return append(b, b...) },
		"duplicate-cookie-only": func(b []byte) []byte {
			next := append([]byte(nil), b...)
			binary.NativeEndian.PutUint32(next[16+68:16+72], 23456)
			return append(b, next...)
		},
		"duplicate-inode-only": func(b []byte) []byte {
			next := append([]byte(nil), b...)
			binary.NativeEndian.PutUint32(next[16+44:16+48], 123)
			return append(b, next...)
		},
		"oversize-datagram": func(b []byte) []byte { return append(b, make([]byte, maxPendingTCPDatagramQEMU)...) },
	} {
		t.Run(name, func(t *testing.T) {
			dump := &pendingTCPDumpQEMU{seq: 1, port: 42}
			if err := dump.consume(change(pendingTCPMessageQEMU(unix.SOCK_DIAG_BY_FAMILY, pendingTCPWireFixtureQEMU()))); !errors.Is(err, ErrUnavailable) {
				t.Fatal("bad dump accepted", err)
			}
			if rows, err := dump.result(); !errors.Is(err, ErrUnavailable) || rows != nil {
				t.Fatal("failed dump published rows", err)
			}
			if err := dump.consume(pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4))); !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed dump revived on a valid completion", err)
			}
		})
	}
}

func TestPendingTCPWireDumpCompletionAndEarlierRowsFailClosed(t *testing.T) {
	for name, tail := range map[string][]byte{
		"missing-status":   pendingTCPMessageQEMU(unix.NLMSG_DONE, nil),
		"failed-status":    pendingTCPMessageQEMU(unix.NLMSG_DONE, []byte{1, 0, 0, 0}),
		"trailing-message": append(pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4)), pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4))...),
		"trailing-byte":    append(pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4)), 0),
		"malformed-next":   {0},
	} {
		t.Run(name, func(t *testing.T) {
			dump := &pendingTCPDumpQEMU{seq: 1, port: 42}
			if err := dump.consume(pendingTCPMessageQEMU(unix.SOCK_DIAG_BY_FAMILY, pendingTCPWireFixtureQEMU())); err != nil {
				t.Fatal(err)
			}
			if err := dump.consume(tail); !errors.Is(err, ErrUnavailable) {
				t.Fatal("invalid completion accepted", err)
			}
			if rows, err := dump.result(); !errors.Is(err, ErrUnavailable) || rows != nil {
				t.Fatal("prior partial rows survived a later malformed datagram", err)
			}
		})
	}
	for _, dump := range []*pendingTCPDumpQEMU{nil, {}, {seq: 1}, {port: 42}} {
		if err := dump.consume(pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4))); !errors.Is(err, ErrUnavailable) {
			t.Fatal("unbound decoder accepted a dump", err)
		}
	}
	dump := &pendingTCPDumpQEMU{seq: 1, port: 42}
	if err := dump.consume(pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4))); err != nil {
		t.Fatal("complete empty inventory refused", err)
	}
	if rows, err := dump.result(); err != nil || len(rows) != 0 {
		t.Fatal("empty inventory could not be observed", err)
	}
	if err := dump.consume(pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4))); !errors.Is(err, ErrUnavailable) {
		t.Fatal("completed decoder reused", err)
	}
}

func TestPendingTCPWireDumpBoundsRowsAndBytes(t *testing.T) {
	for _, large := range []bool{false, true} {
		dump := &pendingTCPDumpQEMU{seq: 1, port: 42}
		limit := maxPendingTCPSocketsQEMU
		if large {
			limit = 64 // 64 * 4088 bytes fits; the next record exceeds 256 KiB.
		}
		for i := 0; i <= limit; i++ {
			payload := pendingTCPWireFixtureQEMU()
			binary.NativeEndian.PutUint32(payload[44:48], uint32(i+1))
			binary.NativeEndian.PutUint32(payload[68:72], uint32(i+1))
			if large {
				attr := make([]byte, 4000)
				binary.NativeEndian.PutUint16(attr[:2], uint16(len(attr)))
				payload = append(payload, attr...)
			}
			err := dump.consume(pendingTCPMessageQEMU(unix.SOCK_DIAG_BY_FAMILY, payload))
			if i < limit && err != nil {
				t.Fatal("within-bound record refused", large, i, err)
			}
			if i == limit && !errors.Is(err, ErrUnavailable) {
				t.Fatal("over-bound dump accepted", large, err)
			}
		}
		if rows, err := dump.result(); !errors.Is(err, ErrUnavailable) || rows != nil {
			t.Fatal("bounded failure published partial rows", err)
		}
	}
}

func TestPendingTCPWireExtensionBoundsAndNonAuthority(t *testing.T) {
	for count := 0; count <= 33; count++ {
		payload := pendingTCPWireFixtureQEMU()
		for i := 0; i < count; i++ {
			attr := make([]byte, 8)
			binary.NativeEndian.PutUint16(attr[:2], 5)
			binary.NativeEndian.PutUint16(attr[2:4], 60000) // Unknown repeatable extension.
			attr[4] = 99
			payload = append(payload, attr...)
		}
		observed, err := parsePendingTCPSocketQEMU(payload)
		if count <= 32 && (err != nil || observed.inode != 12345 || observed.cookie != 0x5566778811223344) {
			t.Fatal("bounded unknown extensions altered identity", count, err)
		}
		if count == 33 && (!errors.Is(err, ErrUnavailable) || observed != (pendingTCPSocketQEMU{})) {
			t.Fatal("extension bound bypassed", err)
		}
	}
}

func TestPendingTCPWireExactRecordLimit(t *testing.T) {
	for _, size := range []int{4024, 4025} {
		attr := make([]byte, size)
		binary.NativeEndian.PutUint16(attr[:2], uint16(size))
		observed, err := parsePendingTCPSocketQEMU(append(pendingTCPWireFixtureQEMU(), attr...))
		if size == 4024 && (err != nil || observed.inode != 12345) {
			t.Fatal("exact record limit refused", err)
		}
		if size == 4025 && (!errors.Is(err, ErrUnavailable) || observed != (pendingTCPSocketQEMU{})) {
			t.Fatal("record limit plus one accepted", err)
		}
	}
}

func FuzzPendingTCPWireDump(f *testing.F) {
	packet := pendingTCPMessageQEMU(unix.SOCK_DIAG_BY_FAMILY, pendingTCPWireFixtureQEMU())
	done := pendingTCPMessageQEMU(unix.NLMSG_DONE, make([]byte, 4))
	f.Add(packet)
	f.Add(done)
	f.Add(append(packet, done...))
	f.Add([]byte{0})
	f.Fuzz(func(t *testing.T, data []byte) {
		dump := &pendingTCPDumpQEMU{seq: 1, port: 42}
		err := dump.consume(data)
		rows, resultErr := dump.result()
		if err != nil && (resultErr == nil || rows != nil) {
			t.Fatal("failed framing exposed partial identities")
		}
		if resultErr != nil {
			if rows != nil {
				t.Fatal("refused inventory returned rows")
			}
			return
		}
		if len(rows) > maxPendingTCPSocketsQEMU {
			t.Fatal("record bound bypassed")
		}
		for i, row := range rows {
			if !row.local.Addr().Is4() || !row.peer.Addr().Is4() || row.local.Port() == 0 || row.peer.Port() == 0 ||
				row.local.Addr().IsUnspecified() || row.peer.Addr().IsUnspecified() || row.inode == 0 || row.cookie == 0 || row.cookie == ^uint64(0) {
				t.Fatal("incomplete socket identity")
			}
			for _, previous := range rows[:i] {
				if previous.inode == row.inode || previous.cookie == row.cookie {
					t.Fatal("ambiguous inventory")
				}
			}
		}
	})
}
