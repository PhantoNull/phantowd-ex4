//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"fmt"
	"strconv"
	"strings"
)

// PendingHandleObservationQEMU is copied private fixture metadata, not a lease,
// server file identity or WRITE authority. Never exported through HTTP/logs.
type PendingHandleObservationQEMU struct {
	SessionID, PersistentID, VolatileID uint64
	TreeID                              uint32
}

const pendingHandlePrefixQEMU = "PHANTOWD_SMB_CLIENT_HANDLE_NOTICE "

func (h PendingHandleObservationQEMU) valid() bool {
	return h.SessionID != 0 && h.SessionID != ^uint64(0) &&
		h.PersistentID != 0 && h.PersistentID != ^uint64(0) &&
		h.VolatileID != 0 && h.VolatileID != ^uint64(0) && h.TreeID != 0 && h.TreeID != ^uint32(0)
}

func (h PendingHandleObservationQEMU) notice() string {
	return fmt.Sprintf("%ssession=%d tree=%d persistent=%d volatile=%d scope=qemu-only proof=false\n",
		pendingHandlePrefixQEMU, h.SessionID, h.TreeID, h.PersistentID, h.VolatileID)
}

func parsePendingHandleQEMU(line []byte) (PendingHandleObservationQEMU, error) {
	var result PendingHandleObservationQEMU
	if len(line) > 256 {
		return result, ErrReviewRequired
	}
	fields := strings.Split(string(line), " ")
	if len(fields) != 7 {
		return result, ErrReviewRequired
	}
	var values [4]uint64
	for index, name := range []string{"session=", "tree=", "persistent=", "volatile="} {
		if !strings.HasPrefix(fields[index+1], name) {
			return result, ErrReviewRequired
		}
		bits := 64
		if index == 1 {
			bits = 32
		}
		value, err := strconv.ParseUint(strings.TrimPrefix(fields[index+1], name), 10, bits)
		if err != nil {
			return result, ErrReviewRequired
		}
		values[index] = value
	}
	result = PendingHandleObservationQEMU{SessionID: values[0], TreeID: uint32(values[1]), PersistentID: values[2], VolatileID: values[3]}
	if !result.valid() || result.notice() != string(line) {
		return PendingHandleObservationQEMU{}, ErrReviewRequired
	}
	return result, nil
}

// Strict ordered bounded telemetry. Incomplete prefixes are not observations.
// CLOSE must repeat the original cached tuple, never replace/rebind it.
func pendingHandleNoticesQEMU(stdout, stderr []byte, closing bool, initial PendingHandleObservationQEMU) (PendingHandleObservationQEMU, bool, error) {
	if len(stderr) != 0 || len(stdout) > 4096 {
		return PendingHandleObservationQEMU{}, false, ErrReviewRequired
	}
	observed := initial
	if !closing {
		end := bytes.IndexByte(stdout, '\n')
		if end < 0 {
			if len(stdout) > 256 || (!bytes.HasPrefix([]byte(pendingHandlePrefixQEMU), stdout) && !bytes.HasPrefix(stdout, []byte(pendingHandlePrefixQEMU))) {
				return PendingHandleObservationQEMU{}, false, ErrReviewRequired
			}
			return PendingHandleObservationQEMU{}, false, nil
		}
		var err error
		observed, err = parsePendingHandleQEMU(stdout[:end+1])
		if err != nil {
			return PendingHandleObservationQEMU{}, false, err
		}
	} else if !initial.valid() {
		return PendingHandleObservationQEMU{}, false, ErrReviewRequired
	}
	expected := []byte(observed.notice() + pendingOpenNoticeQEMU)
	if closing {
		expected = append(expected, []byte(observed.notice()+pendingCloseNoticeQEMU)...)
	}
	if !bytes.HasPrefix(expected, stdout) {
		return PendingHandleObservationQEMU{}, false, ErrReviewRequired
	}
	ready := bytes.Equal(stdout, expected)
	if !ready {
		return PendingHandleObservationQEMU{}, false, nil
	}
	return observed, true, nil
}

// InitialHandleObservationQEMU returns only the cached startup observation,
// not a live re-observation. Containing composition retains/rechecks all code,
// process/connection and server references. No raw notice leaves this adapter.
func (c *PendingClientQEMU) InitialHandleObservationQEMU(ctx context.Context) (PendingHandleObservationQEMU, error) {
	if err := c.enter(ctx); err != nil {
		return PendingHandleObservationQEMU{}, err
	}
	defer func() { <-c.gate }()
	if !c.handleMode || !c.handleInitial.valid() || c.review || !c.started || c.settled || c.closeSent || c.process == nil || c.process.exited() {
		return PendingHandleObservationQEMU{}, ErrReviewRequired
	}
	if err := c.recheckPins(); err != nil {
		return PendingHandleObservationQEMU{}, c.fail(err)
	}
	if err := ctx.Err(); err != nil {
		return PendingHandleObservationQEMU{}, err
	}
	return c.handleInitial, nil
}
