//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// Fixed fixture synchronization, not request or record authority. Observe only
// original queue occupancy, then cancel once. An observation error is terminal;
// never consume, decode, retry an error or substitute an endpoint.
func cancelOnQueuedCaptureQEMU(ctx context.Context, channel *pendingServerPacketQEMU, cancel context.CancelFunc) error {
	if ctx == nil || channel == nil || cancel == nil {
		return ErrInvalid
	}
	bounded, done := context.WithTimeout(ctx, 5*time.Second)
	defer done()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		n, err := channel.queuedBytesQEMU(bounded)
		if err != nil {
			return err
		}
		if n == 88 {
			if err := bounded.Err(); err != nil {
				return err
			}
			cancel()
			return nil
		}
		select {
		case <-bounded.Done():
			return bounded.Err()
		case <-ticker.C:
		}
	}
}

func captureCancelReadFixtureQEMU() bool {
	if serverObserverCodeGuardQEMU() != nil {
		return false
	}
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		return false
	}
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_capture_cancel_read_fixture=1" {
			return true
		}
	}
	return false
}

func captureCancelReadProofQEMU(ctx context.Context, o *pendingClientOwnerQEMU, r *serverObserverRuntimeQEMU, original *os.File, initial unix.Stat_t) error {
	if ctx == nil || o == nil || r == nil || original == nil || !captureCancelReadFixtureQEMU() || o.capturePeer != r || r.channel == nil || r.channel.sequence != 0 {
		return ErrInvalid
	}
	if n, err := r.channel.queuedBytesQEMU(ctx); err != nil || n != 0 {
		return errors.Join(ErrMismatch, err)
	}
	collect, cancel := context.WithCancel(ctx)
	defer cancel()
	witness, stopWitness := context.WithCancel(ctx)
	defer stopWitness()
	observed := make(chan error, 1)
	go func() { observed <- cancelOnQueuedCaptureQEMU(witness, r.channel, cancel) }()
	frame, readErr := o.readCaptureFrameQEMU(collect)
	stopWitness()
	// Join the bounded witness before touching reviewed state or returning.
	if err := <-observed; err != nil {
		return errors.Join(ErrMismatch, err, readErr)
	}
	if !errors.Is(collect.Err(), context.Canceled) || !errors.Is(readErr, context.Canceled) || !errors.Is(readErr, ErrReviewRequired) || frame != (pendingServerPacketObservationQEMU{}) || !o.review || !r.review || r.channel.sequence != 0 {
		return errors.Join(ErrMismatch, readErr)
	}
	return captureQueuedReviewProofQEMU(ctx, o, r, original, initial)
}
