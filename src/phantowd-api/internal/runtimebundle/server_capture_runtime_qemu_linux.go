//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"
	"strings"
)

// Construction-only private roles: never a caller-selected operation/profile.
type serverObserverProfileQEMU uint8

const (
	serverObserverNegotiationProfileQEMU serverObserverProfileQEMU = iota
	serverObserverCaptureProfileQEMU
	serverCaptureModuleObjectQEMU = "usr/lib/samba/vfs/phantowd_open_qemu.so"
)

func serverCaptureDocumentsQEMU() map[string]string {
	documents := serverObserverDocumentsQEMU()
	configuration := strings.Replace(documents["samba/smb.conf"],
		"server max protocol = SMB3_02\n", "server max protocol = SMB3_11\nserver signing = mandatory\n", 1)
	documents["samba/smb.conf"] = configuration + "valid users = nobody\nvfs objects = phantowd_open_qemu\n"
	return documents
}

// Fixed dedicated capture construction. The independently expected Plan must
// include the original module/closure and separately built fixed bootstrap;
// no per-call input injection or generic-launcher widening. This constructor
// alone does not authorize frame consumption or grant a server-open lease.
func newServerCaptureRuntimeQEMU(ctx context.Context, plan *Plan, code, configuration, state *os.File, shares [2]*os.File) (*serverObserverRuntimeQEMU, error) {
	if ctx == nil || serverObserverCodeGuardQEMU() != nil {
		return nil, ErrInvalid
	}
	commandLine, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(commandLine) > 4096 {
		return nil, ErrInvalid
	}
	for _, field := range strings.Fields(string(commandLine)) {
		if field == "phantowd_capture_runtime_fixture=1" {
			return newServerObserverProfileRuntimeQEMU(ctx, plan, code, configuration, state, shares, serverObserverCaptureProfileQEMU)
		}
	}
	return nil, ErrInvalid
}
