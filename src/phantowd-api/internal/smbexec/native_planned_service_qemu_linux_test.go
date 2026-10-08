//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNativePlannedServiceRefusesAbsentAuthorityBeforeOwnershipTransfer(t *testing.T) {
	ctx := context.Background()
	for _, inputs := range []NativePlannedInputsQEMU{
		{},
		{Identity: &identityowner.Owner{}},
		{Backend: &NativeBackendQEMU{}},
		{Identity: &identityowner.Owner{}, Storage: &mountowner.MountedVolumeSet{},
			Shares: &mountowner.ServiceSharePinsQEMU{}, Backend: &NativeBackendQEMU{}},
	} {
		if service, err := NewNativePlannedServiceQEMU(ctx, inputs); service != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("incomplete native composition acquired authority:", err)
		}
	}
	var service *NativePlannedServiceQEMU
	for _, operation := range []func(context.Context) error{service.Observe, service.Close} {
		if err := operation(ctx); !errors.Is(err, ErrInvalid) {
			t.Fatal("absent service accepted a lifecycle operation:", err)
		}
	}
	if _, err := service.Status(); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent service published an authority observation:", err)
	}
}

func TestNativePlannedStartRefusesMissingAuthority(t *testing.T) {
	var service *NativePlannedServiceQEMU
	if err := service.Start(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent planned service admitted startup:", err)
	}
}

func TestNativePlannedDataRefusesAbsentCanceledAndBusyAuthority(t *testing.T) {
	var absent *NativePlannedServiceQEMU
	if err := absent.VerifyDataAccess(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent planned service admitted a data operation:", err)
	}
	service := &NativePlannedServiceQEMU{gate: make(chan struct{}, 1)}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.VerifyDataAccess(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled data qualification proceeded:", err)
	}
	service.gate <- struct{}{}
	err := service.VerifyDataAccess(context.Background())
	<-service.gate
	if !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("busy planned service admitted a data operation:", err)
	}
	if err := service.VerifyDataAccess(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		t.Fatal("unstarted planned service admitted a data operation:", err)
	}
}
