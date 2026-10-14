//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"io"
	"strings"
	"testing"
)

func TestPendingPeerExitProofRequiresExactReceiptAndBoundedDiagnostics(t *testing.T) {
	timing := "PHANTOWD_DIAG_NATIVE_WORKER operation=status phase=execution elapsed_ms=1 remaining_ms=30000 parent_done=false failed=false cause=none qualifying=false scope=qemu-only\n"
	for _, telemetry := range []string{"", timing, strings.Repeat(timing, 3)} {
		if got, err := pendingPeerExitProofQEMU(telemetry + pendingPeerExitChildProofQEMU); err != nil || got != telemetry {
			t.Fatal("exact child receipt refused", err)
		}
	}
	for _, bad := range []string{"", timing, pendingPeerExitMarkerQEMU, pendingPeerExitChildProofQEMU + pendingPeerExitChildProofQEMU,
		strings.TrimSuffix(pendingPeerExitChildProofQEMU, "\n"), "arbitrary\n" + pendingPeerExitChildProofQEMU,
		strings.TrimSuffix(timing, "\n") + pendingPeerExitChildProofQEMU, strings.Repeat(timing, 513) + pendingPeerExitChildProofQEMU,
		strings.Replace(pendingPeerExitChildProofQEMU, "inputs_retained=true", "inputs_retained=false", 1),
		strings.Replace(timing, "operation=status", "operation=unknown", 1) + pendingPeerExitChildProofQEMU} {
		if got, err := pendingPeerExitProofQEMU(bad); err == nil || got != "" {
			t.Fatal("incomplete/diagnostic-only/foreign/repeated proof accepted")
		}
	}
	var output pendingPeerExitOutputQEMU
	if n, err := io.Copy(&output, strings.NewReader(strings.Repeat("a", 65536))); n != 65536 || err != nil || len(output.String()) != 65536 {
		t.Fatal(n, err)
	}
	if n, err := io.Copy(&output, strings.NewReader("a")); n != 0 || err == nil || len(output.String()) != 65536 {
		t.Fatal("copy bypassed output cap", n, err)
	}
}
