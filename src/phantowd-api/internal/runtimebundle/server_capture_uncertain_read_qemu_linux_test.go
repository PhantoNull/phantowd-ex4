//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestServerCaptureQueuedObservationNeverConsumesOrAdvances(t *testing.T) {
	pair, err := newPendingServerPacketQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pair.close()
	if n, err := pair.queuedBytesQEMU(context.Background()); err != nil || n != 0 {
		t.Fatal("empty original queue not observed", n, err)
	}
	if err := unix.Send(int(pair.sender.Fd()), make([]byte, 88), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
		t.Fatal(err)
	}
	for range 3 {
		if n, err := pair.queuedBytesQEMU(context.Background()); err != nil || n != 88 || pair.sequence != 0 || pair.queueEmpty() {
			t.Fatal("observation consumed/published queued data", n, err)
		}
	}
	if n, err := pair.queuedBytesQEMU(context.Background()); err != nil || n != 88 || pair.sequence != 0 {
		t.Fatal("queued record lost")
	}
}

func TestServerCaptureQueuedCancellationDoesNotConsume(t *testing.T) {
	pair, err := newPendingServerPacketQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer pair.close()
	if err := unix.Send(int(pair.sender.Fd()), make([]byte, 88), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
		t.Fatal(err)
	}
	collect, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := cancelOnQueuedCaptureQEMU(context.Background(), pair, cancel); err != nil || !errors.Is(collect.Err(), context.Canceled) {
		t.Fatal("original queued record did not cancel collection", err)
	}
	if n, err := pair.queuedBytesQEMU(context.Background()); err != nil || n != 88 || pair.sequence != 0 {
		t.Fatal("cancellation consumed or published queued metadata", n, err)
	}
}

func TestServerCaptureQueueWitnessErrorsDoNotCancel(t *testing.T) {
	for _, name := range []string{"canceled", "oversized", "empty-deadline"} {
		t.Run(name, func(t *testing.T) {
			pair, err := newPendingServerPacketQEMU(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer pair.close()
			ctx, stop := context.WithCancel(context.Background())
			defer stop()
			want, size := error(context.Canceled), 88
			switch name {
			case "canceled":
				stop()
			case "oversized":
				want, size = ErrMismatch, 89
			case "empty-deadline":
				var timeout context.CancelFunc
				ctx, timeout = context.WithTimeout(ctx, 10*time.Millisecond)
				defer timeout()
				want, size = context.DeadlineExceeded, 0
			}
			if size != 0 {
				if err := unix.Send(int(pair.sender.Fd()), make([]byte, size), unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL); err != nil {
					t.Fatal(err)
				}
			}
			collect, cancel := context.WithCancel(context.Background())
			defer cancel()
			attempts := 0
			if err := cancelOnQueuedCaptureQEMU(ctx, pair, func() { attempts++; cancel() }); !errors.Is(err, want) || attempts != 0 || collect.Err() != nil {
				t.Fatal("uncertain witness canceled collection or lost cause", err, attempts)
			}
			if n, err := unix.IoctlGetInt(int(pair.receiver.Fd()), unix.SIOCINQ); err != nil || n != size || pair.sequence != 0 {
				t.Fatal("refusal consumed/published queued record", n, err)
			}
		})
	}
}
