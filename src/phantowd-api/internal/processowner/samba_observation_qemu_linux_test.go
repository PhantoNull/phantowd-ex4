//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"
	"testing"
)

func TestSambaStateObservationRefusesNativeHostWithoutConsumingCallers(t *testing.T) {
	if model, _ := os.ReadFile("/sys/firmware/devicetree/base/model"); string(model) == "ARM Versatile PB\x00" {
		t.Skip("native refusal only; positive and late-input refusal run in the mandatory ARMv5 fixture")
	}
	caller, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer caller.Close()
	var directories [7]*os.File
	for index := range directories {
		directories[index] = caller
	}
	for range 16 {
		capture, err := NewSambaStateObservationCaptureQEMU(caller, caller, directories)
		if capture != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("native caller acquired the QEMU state worker", err)
		}
		if _, err := caller.Stat(); err != nil {
			t.Fatal("native refusal consumed its caller", err)
		}
	}
}
