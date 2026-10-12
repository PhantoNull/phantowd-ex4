//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"testing"

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
