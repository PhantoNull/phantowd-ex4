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

func TestNativePlannedSupervisionRefusesMissingAuthority(t *testing.T) {
	var absent *NativePlannedServiceQEMU
	if err := absent.Supervise(context.Background(), time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent planned service admitted supervision:", err)
	}
	var uninitialized NativePlannedServiceQEMU
	if err := uninitialized.Supervise(context.Background(), time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatal("uninitialized planned service admitted supervision:", err)
	}
}

func TestNativePlannedCloseFailurePublishesStickyReview(t *testing.T) {
	// Negative-only admission fixture: this invalid runtime cannot own or start
	// a process. Exercise Close/Status, never fabricate a healthy authority.
	service := &NativePlannedServiceQEMU{gate: make(chan struct{}, 1), inputs: NativePlannedInputsQEMU{
		Backend: &NativeBackendQEMU{runtime: &runtimebundle.NativeSambaRuntimeQEMU{}},
	}}
	if err := service.Close(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		t.Fatal("invalid runtime close was reported as settled:", err)
	}
	status, err := service.Status()
	if err != nil || status.State != "review-required" || status.RuntimeClosed || status.IdentityRetained || status.SharesRetained {
		t.Fatal("failed runtime close did not publish unqualified review:", status, err)
	}
	if err := service.Close(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		t.Fatal("uncertain runtime close was retried as success:", err)
	}
	unchanged, err := service.Status()
	if err != nil || unchanged != status {
		t.Fatal("repeated uncertain close changed review:", unchanged, err)
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

func TestNativePlannedReviewedCloseRefusesBeforeRuntimeAccess(t *testing.T) {
	// Negative-only admission fixture, never a fabricated healthy authority.
	// No backend exists: review must refuse before accessing any runtime alias.
	service := &NativePlannedServiceQEMU{gate: make(chan struct{}, 1), review: true}
	service.publish()
	before, err := service.Status()
	if err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := service.Close(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
			t.Fatal("reviewed close accessed runtime or reported settlement:", err)
		}
		after, err := service.Status()
		if err != nil || after != before {
			t.Fatal("reviewed close changed retained telemetry:", after, err)
		}
	}
}
