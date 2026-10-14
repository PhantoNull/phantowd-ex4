//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"
)

const (
	maxPendingTCPRecordQEMU   = 4096
	maxPendingTCPDatagramQEMU = 64 << 10
	maxPendingTCPDumpQEMU     = 256 << 10
	maxPendingTCPSocketsQEMU  = 256
)

// Pure wire observations only. No socket, process binding, descriptor, SMB
// handle or request authority is created by this decoder.
type pendingTCPSocketQEMU struct {
	local, peer netip.AddrPort
	cookie      uint64
	inode, uid  uint32
	interfaceID uint32
}

// Completion means multipart framing only, not an atomic socket snapshot.
type pendingTCPDumpQEMU struct {
	seq, port uint32
	bytes     int
	done      bool
	failed    bool
	rows      []pendingTCPSocketQEMU
}

func (d *pendingTCPDumpQEMU) consume(data []byte) (result error) {
	if d == nil {
		return ErrUnavailable
	}
	defer func() {
		if result != nil {
			d.failed = true
			d.rows = nil // Even earlier partial datagrams cannot become a result.
		}
	}()
	if d.seq == 0 || d.port == 0 || d.done || d.failed || d.bytes < 0 ||
		len(data) < 16 || len(data) > maxPendingTCPDatagramQEMU || d.bytes > maxPendingTCPDumpQEMU-len(data) {
		return ErrUnavailable
	}
	d.bytes += len(data)
	for len(data) > 0 {
		if len(data) < 16 {
			return ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint32(data[:4]))
		if n < 16 || n > len(data) || (n+3)&^3 > len(data) ||
			binary.NativeEndian.Uint16(data[6:8]) != unix.NLM_F_MULTI ||
			binary.NativeEndian.Uint32(data[8:12]) != d.seq || binary.NativeEndian.Uint32(data[12:16]) != d.port {
			return ErrUnavailable
		}
		kind := binary.NativeEndian.Uint16(data[4:6])
		payload := data[16:n]
		if kind == unix.NLMSG_DONE {
			if len(payload) != 4 || binary.NativeEndian.Uint32(payload) != 0 || (n+3)&^3 != len(data) {
				return ErrUnavailable
			}
			d.done = true
			return nil
		}
		if kind != unix.SOCK_DIAG_BY_FAMILY || len(d.rows) >= maxPendingTCPSocketsQEMU {
			return ErrUnavailable
		}
		row, err := parsePendingTCPSocketQEMU(payload)
		if err != nil {
			return ErrUnavailable
		}
		for _, previous := range d.rows {
			if previous.inode == row.inode || previous.cookie == row.cookie {
				return ErrUnavailable
			}
		}
		d.rows = append(d.rows, row)
		data = data[(n+3)&^3:]
	}
	return nil
}

func (d *pendingTCPDumpQEMU) result() ([]pendingTCPSocketQEMU, error) {
	if d == nil || d.failed || !d.done || d.seq == 0 || d.port == 0 {
		return nil, ErrUnavailable
	}
	return slices.Clone(d.rows), nil
}

func parsePendingTCPSocketQEMU(data []byte) (pendingTCPSocketQEMU, error) {
	if len(data) < 72 || len(data) > maxPendingTCPRecordQEMU || data[0] != unix.AF_INET || data[1] != 1 {
		return pendingTCPSocketQEMU{}, ErrUnavailable
	}
	var zero [12]byte
	if !bytes.Equal(data[12:24], zero[:]) || !bytes.Equal(data[28:40], zero[:]) {
		return pendingTCPSocketQEMU{}, ErrUnavailable
	}
	// Extensions are not consumed as authority. Only their bounded framing is
	// checked; kernel-added padding or unknown attributes may repeat.
	attrs := data[72:]
	for count := 0; len(attrs) > 0; count++ {
		if count >= 32 || len(attrs) < 4 {
			return pendingTCPSocketQEMU{}, ErrUnavailable
		}
		n := int(binary.NativeEndian.Uint16(attrs[:2]))
		aligned := (n + 3) &^ 3
		if n < 4 || aligned > len(attrs) {
			return pendingTCPSocketQEMU{}, ErrUnavailable
		}
		attrs = attrs[aligned:]
	}
	var local, peer [4]byte
	copy(local[:], data[8:12])
	copy(peer[:], data[24:28])
	observed := pendingTCPSocketQEMU{
		local:       netip.AddrPortFrom(netip.AddrFrom4(local), binary.BigEndian.Uint16(data[4:6])),
		peer:        netip.AddrPortFrom(netip.AddrFrom4(peer), binary.BigEndian.Uint16(data[6:8])),
		cookie:      uint64(binary.NativeEndian.Uint32(data[44:48])) | uint64(binary.NativeEndian.Uint32(data[48:52]))<<32,
		interfaceID: binary.NativeEndian.Uint32(data[40:44]),
		uid:         binary.NativeEndian.Uint32(data[64:68]),
		inode:       binary.NativeEndian.Uint32(data[68:72]),
	}
	if observed.local.Port() == 0 || observed.peer.Port() == 0 || observed.local.Addr().IsUnspecified() ||
		observed.peer.Addr().IsUnspecified() || observed.cookie == 0 || observed.cookie == ^uint64(0) || observed.inode == 0 {
		return pendingTCPSocketQEMU{}, ErrUnavailable
	}
	return observed, nil
}
