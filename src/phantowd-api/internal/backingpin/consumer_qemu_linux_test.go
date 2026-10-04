//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"errors"
	"runtime"
	"testing"
)

func TestQEMUWritableConsumerRefusesNonARMBeforeDescriptorAccess(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("native architecture refusal; actual ARM consumer exercised by guest fixture")
	}
	if err := RunQEMUWritableConsumer(); !errors.Is(err, ErrUnavailable) {
		t.Fatal("non-QEMU host entered the write/hold path", err)
	}
}
