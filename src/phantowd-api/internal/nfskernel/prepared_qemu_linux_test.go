//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package nfskernel_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

func TestPreparedQEMURefusesMissingOriginalController(t *testing.T) {
	for _, controller := range []*nfskernel.ControllerQEMU{nil, {}} {
		for _, ctx := range []context.Context{nil, context.Background()} {
			if err := controller.CheckPreparedQEMU(ctx); !errors.Is(err, nfskernel.ErrRefused) {
				t.Fatal("unacquired controller represented as prepared", err)
			}
		}
	}
}
