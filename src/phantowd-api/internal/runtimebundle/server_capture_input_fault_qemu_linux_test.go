//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import "testing"

func TestServerCaptureInputFaultMarkerIsFixedAndUnambiguous(t *testing.T) {
	for _, kind := range []string{"module", "configuration", "channel", "source"} {
		value, err := parseCaptureInputFaultMarkerQEMU([]byte("console=ttyAMA0 phantowd_capture_input_fault_fixture=" + kind + " root=/dev/sda"))
		if err != nil || string(value) != kind {
			t.Fatal("fixed fixture marker refused", kind, err)
		}
	}
	if value, err := parseCaptureInputFaultMarkerQEMU([]byte("root=/dev/sda")); err != nil || value != "" {
		t.Fatal("ordinary fixture was changed")
	}
	for _, input := range []string{"phantowd_capture_input_fault_fixture=unknown", "phantowd_capture_input_fault_fixture=module phantowd_capture_input_fault_fixture=channel", "phantowd_capture_input_fault_fixture=channel phantowd_capture_worker_exit_fixture=1", "phantowd_capture_input_fault_fixture=module/foreign", "phantowd_capture_input_fault_fixture="} {
		if value, err := parseCaptureInputFaultMarkerQEMU([]byte(input)); err == nil || value != "" {
			t.Fatal("foreign/ambiguous fault selector admitted", input)
		}
	}
}
