//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfskernel_test

import (
	"context"
	"runtime"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

func TestControllerQEMURefusesHostAndInvalidLifetimes(t *testing.T) {
	if runtime.GOARCH != "arm" {
		for _, open := range []func(context.Context) (*nfskernel.ControllerQEMU, error){nfskernel.OpenCodeQEMU, nfskernel.OpenRebootQEMU, nfskernel.OpenSmokeQEMU} {
			if k, err := open(context.Background()); err == nil || k != nil {
				t.Fatal("ordinary host admitted to kernel controller")
			}
		}
	}
	for _, k := range []*nfskernel.ControllerQEMU{nil, {}} {
		for _, operation := range []func(context.Context) error{k.Start, k.CheckRunning, k.CheckStopped, k.Stop, k.Close} {
			if operation(nil) == nil || operation(context.Background()) == nil {
				t.Fatal("invalid lifetime admitted")
			}
		}
	}
}
