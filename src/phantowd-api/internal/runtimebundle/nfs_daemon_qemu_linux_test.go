//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"testing"
)

func TestNFSDaemonLifetimeRefusesMissingAndCanceledInputs(t *testing.T) {
	if got, err := newNFSDaemonQEMU(nil, nil, nil, nil, false); got != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context admitted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := newNFSDaemonQEMU(ctx, nil, nil, nil, true); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled preparation lost its cause", err)
	}
	for _, mountd := range []bool{false, true} {
		if got, err := newNFSDaemonQEMU(context.Background(), nil, nil, nil, mountd); got != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("missing original roles admitted", err)
		}
	}
}

func TestNFSDaemonLifetimeZeroAndCopiedHandlesRefuse(t *testing.T) {
	ctx := context.Background()
	for _, value := range []*nfsDaemonQEMU{nil, {}} {
		if value.start(ctx) == nil || value.check(ctx) == nil || value.stop(ctx) == nil || value.close() == nil {
			t.Fatal("invalid daemon lifetime admitted")
		}
	}
	original := &nfsDaemonQEMU{}
	original.original = original
	copied := *original
	if copied.start(ctx) == nil || copied.check(ctx) == nil || copied.stop(ctx) == nil || copied.close() == nil {
		t.Fatal("copied daemon lifetime admitted")
	}
}
