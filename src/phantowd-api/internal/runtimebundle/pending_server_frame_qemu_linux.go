//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"encoding/binary"
	"math"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// Copied private metadata only, never producer, process or execution authority.
// Native C padding/endian are deliberately absent from the fixed wire format.
type pendingServerOpenMetadataQEMU struct {
	session, persistent, volatile, shareFileID uint64
	device, inode, workerUnique                uint64
	tree, workerPID, workerTask, workerVNN     uint32
}

func (m pendingServerOpenMetadataQEMU) valid() bool {
	return m.session != 0 && m.session != math.MaxUint64 &&
		m.persistent != 0 && m.persistent != math.MaxUint64 &&
		m.volatile != 0 && m.volatile != math.MaxUint64 &&
		m.shareFileID != 0 && m.shareFileID != math.MaxUint64 &&
		m.device != 0 && m.inode != 0 && m.workerUnique != 0 && m.workerUnique != math.MaxUint64 &&
		m.tree != 0 && m.tree != math.MaxUint32 && m.workerPID > 1 && m.workerPID <= math.MaxInt32 &&
		m.workerTask == 0 && m.workerVNN == math.MaxUint32
}

func decodePendingServerOpenFrameQEMU(frame []byte, sequence uint32) (pendingServerOpenMetadataQEMU, error) {
	if len(frame) != 88 || string(frame[:8]) != "PWDOPEN\x00" ||
		binary.LittleEndian.Uint16(frame[8:]) != 1 ||
		binary.LittleEndian.Uint16(frame[10:]) != 72 ||
		(sequence != 1 && sequence != 2) || binary.LittleEndian.Uint32(frame[12:]) != sequence {
		return pendingServerOpenMetadataQEMU{}, ErrMismatch
	}
	observed := pendingServerOpenMetadataQEMU{
		session:      binary.LittleEndian.Uint64(frame[16:]),
		persistent:   binary.LittleEndian.Uint64(frame[24:]),
		volatile:     binary.LittleEndian.Uint64(frame[32:]),
		shareFileID:  binary.LittleEndian.Uint64(frame[40:]),
		device:       binary.LittleEndian.Uint64(frame[48:]),
		inode:        binary.LittleEndian.Uint64(frame[56:]),
		workerUnique: binary.LittleEndian.Uint64(frame[64:]),
		tree:         binary.LittleEndian.Uint32(frame[72:]),
		workerPID:    binary.LittleEndian.Uint32(frame[76:]),
		workerTask:   binary.LittleEndian.Uint32(frame[80:]),
		workerVNN:    binary.LittleEndian.Uint32(frame[84:]),
	}
	if !observed.valid() {
		return pendingServerOpenMetadataQEMU{}, ErrMismatch
	}
	return observed, nil
}

// Only a metadata comparison. A containing Owner must still qualify/retain the
// producer and channel and recheck original process/namespace/TCP/local-object
// lifetimes before and after consumption. Equality grants no WRITE authority.
func matchPendingServerOpenMetadataQEMU(observed pendingServerOpenMetadataQEMU, status pendingStatusQEMU, client processowner.PendingHandleObservationQEMU) error {
	if !observed.valid() ||
		observed.session != client.SessionID || observed.tree != client.TreeID ||
		observed.persistent != client.PersistentID || observed.volatile != client.VolatileID ||
		strconv.FormatUint(observed.session, 10) != status.session ||
		strconv.FormatUint(uint64(observed.tree), 10) != status.tree ||
		observed.device != status.device || observed.inode != status.inode ||
		observed.shareFileID != status.shareFileID ||
		strconv.FormatUint(uint64(observed.workerPID), 10) != status.server.PID ||
		strconv.FormatUint(uint64(observed.workerTask), 10) != status.server.TaskID ||
		strconv.FormatUint(uint64(observed.workerVNN), 10) != status.server.VNN ||
		strconv.FormatUint(observed.workerUnique, 10) != status.server.UniqueID {
		return ErrMismatch
	}
	return nil
}
