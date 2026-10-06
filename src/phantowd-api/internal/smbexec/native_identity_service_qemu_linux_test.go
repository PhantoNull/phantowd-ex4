//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
)

func TestNativeIdentityServiceRefusesAbsentAuthority(t *testing.T) {
	ctx := context.Background()
	for _, candidate := range []struct {
		owner   *identityowner.Owner
		backend *NativeBackendQEMU
	}{
		{},
		{owner: &identityowner.Owner{}},
		{backend: &NativeBackendQEMU{}},
		{owner: &identityowner.Owner{}, backend: &NativeBackendQEMU{}},
	} {
		service, err := NewNativeIdentityServiceQEMU(ctx, candidate.owner, [32]byte{1}, candidate.backend)
		if service != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("absent startup-bound authority was admitted:", err)
		}
	}
	var service *NativeIdentityServiceQEMU
	for _, operation := range []func(context.Context) error{service.Start, service.Observe, service.Close} {
		if err := operation(ctx); !errors.Is(err, ErrInvalid) {
			t.Fatal("absent coordinator admitted an operation:", err)
		}
	}
	if err := service.Supervise(ctx, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent coordinator admitted supervision:", err)
	}
	if _, err := service.Status(); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent coordinator published status:", err)
	}
}

func TestNativeIdentityServiceConstructionRefusesCancellationBeforeObservation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	service, err := NewNativeIdentityServiceQEMU(ctx, &identityowner.Owner{}, [32]byte{1}, &NativeBackendQEMU{})
	if service != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled construction proceeded to invalid authority observation:", err)
	}
	for _, ctx := range []context.Context{nil, context.Background()} {
		service, err := NewNativeIdentityServiceQEMU(ctx, &identityowner.Owner{}, [32]byte{}, &NativeBackendQEMU{})
		if service != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("absent context/fingerprint acquired authority:", err)
		}
	}
}
