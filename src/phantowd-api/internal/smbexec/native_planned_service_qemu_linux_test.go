//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func TestNativePlannedDataBoundaryPreservesCauseAndOnlyFixedStages(t *testing.T) {
	private := errors.New("private-credential/path\nFAKE_READY")
	for _, stage := range []string{"before-runtime", "runtime", "after-runtime"} {
		cause := errors.Join(private, context.DeadlineExceeded, runtimebundle.ErrReviewRequired)
		failure := &nativePlannedDataFailureQEMU{stage: stage, cause: cause}
		wrapped := errors.Join(errors.New("outer-private-context"), failure)
		if got := ObserveNativePlannedDataStageQEMU(wrapped); got != stage {
			t.Fatal("fixed boundary not observed", got)
		}
		if !errors.Is(wrapped, private) || !errors.Is(wrapped, context.DeadlineExceeded) || !errors.Is(wrapped, runtimebundle.ErrReviewRequired) || strings.Contains(failure.Error(), "private") {
			t.Fatal("annotation changed or disclosed cause")
		}
	}
	for _, invalid := range []error{nil, private, (*nativePlannedDataFailureQEMU)(nil),
		&nativePlannedDataFailureQEMU{stage: "runtime"},
		&nativePlannedDataFailureQEMU{stage: private.Error(), cause: private},
	} {
		if got := ObserveNativePlannedDataStageQEMU(invalid); got != "" {
			t.Fatal("missing or arbitrary stage accepted", got)
		}
	}
	first := &nativePlannedDataFailureQEMU{stage: "before-runtime", cause: private}
	second := &nativePlannedDataFailureQEMU{stage: "after-runtime", cause: context.Canceled}
	if got := ObserveNativePlannedDataStageQEMU(errors.Join(first, second)); got != "before-runtime" {
		t.Fatal("later cleanup displaced first boundary", got)
	}
	var absent *NativePlannedServiceQEMU
	if err := absent.VerifyDataAccess(context.Background()); !errors.Is(err, ErrInvalid) || ObserveNativePlannedDataStageQEMU(err) != "" {
		t.Fatal("unadmitted service invented a data boundary", err)
	}
}

func TestPlannedDataRefusalContextIsSnapshotNotCauseOrCleanupTime(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	state := nativePlannedRefusalContextQEMU(ctx)
	cancel() // Models cancellation during later quarantine, not at the refusal.
	private := errors.New("private-path-and-credential")
	failure := &nativePlannedDataFailureQEMU{stage: "after-runtime", cause: private, refusalContext: state}
	if ObserveNativePlannedDataContextQEMU(failure) != "live" || errors.Is(failure, context.Canceled) || !errors.Is(failure, private) {
		t.Fatal("later cleanup cancellation rewrote the refusal or original cause")
	}
	if nativePlannedRefusalContextQEMU(ctx) != "canceled" {
		t.Fatal("canceled state missing")
	}
	expired, stop := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer stop()
	if nativePlannedRefusalContextQEMU(expired) != "deadline" || nativePlannedRefusalContextQEMU(nil) != "" {
		t.Fatal("invalid/expired context state")
	}
	failure.refusalContext = "deadline"
	if ObserveNativePlannedDataContextQEMU(failure) != "deadline" || errors.Is(failure, context.DeadlineExceeded) {
		t.Fatal("context observation was promoted into hidden error causality")
	}
	for _, bad := range []error{nil, private, (*nativePlannedDataFailureQEMU)(nil),
		&nativePlannedDataFailureQEMU{stage: "after-runtime", refusalContext: "deadline"},
		&nativePlannedDataFailureQEMU{stage: "private-stage", cause: private, refusalContext: "deadline"},
		&nativePlannedDataFailureQEMU{stage: "after-runtime", cause: private, refusalContext: private.Error()},
	} {
		if ObserveNativePlannedDataContextQEMU(bad) != "" {
			t.Fatal("unobserved or arbitrary context label accepted")
		}
	}
}

type refuseAfterAdmissionContextQEMU struct {
	context.Context
	calls int
}

func (c *refuseAfterAdmissionContextQEMU) Err() error {
	c.calls++
	if c.calls > 1 {
		return context.DeadlineExceeded
	}
	return nil
}

func TestPlannedDataActualRefusalCapturesContextBeforeQuarantine(t *testing.T) {
	// Deliberately incomplete inputs: fail source verification before any OS
	// operation. The zero runtime also refuses stop before process authority.
	// This is a real method refusal test, NOT an admitted healthy NAS service.
	s := &NativePlannedServiceQEMU{gate: make(chan struct{}, 1), started: true,
		inputs: NativePlannedInputsQEMU{Shares: &mountowner.ServiceSharePinsQEMU{},
			Storage: &mountowner.MountedVolumeSet{}, Backend: &NativeBackendQEMU{runtime: &runtimebundle.NativeSambaRuntimeQEMU{}}}}
	ctx := &refuseAfterAdmissionContextQEMU{Context: context.Background()}
	err := s.VerifyDataAccess(ctx)
	if err == nil || ObserveNativePlannedDataStageQEMU(err) != "before-runtime" || ObserveNativePlannedDataContextQEMU(err) != "deadline" ||
		!s.review || s.closed || ctx.calls != 2 || errors.Is(err, context.DeadlineExceeded) {
		t.Fatal("actual refusal lost context snapshot, invented cause or released review", err, ctx.calls)
	}
	if next := s.VerifyDataAccess(context.Background()); ObserveNativePlannedDataContextQEMU(next) != "" {
		t.Fatal("already-reviewed refusal invented new observation", next)
	}
}

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

func TestNativePlannedHeldSessionRefusesMissingCanceledBusyAndUnstartedAuthority(t *testing.T) {
	var absent *NativePlannedServiceQEMU
	if err := absent.StartHeldSessionQEMU(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent service admitted held session:", err)
	}
	service := &NativePlannedServiceQEMU{gate: make(chan struct{}, 1)}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.StartHeldSessionQEMU(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled held session admission proceeded:", err)
	}
	service.gate <- struct{}{}
	err := service.StartHeldSessionQEMU(context.Background())
	<-service.gate
	if !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("competing held session admission proceeded:", err)
	}
	if err := service.StartHeldSessionQEMU(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		t.Fatal("unstarted service accessed backend:", err)
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

func TestNativePlannedExitSupervisionRefusesMissingCanceledAndBusyAuthority(t *testing.T) {
	var absent *NativePlannedServiceQEMU
	if err := absent.SuperviseExitFaultQEMU(context.Background(), time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatal("absent service admitted synthetic exit:", err)
	}
	service := &NativePlannedServiceQEMU{gate: make(chan struct{}, 1)}
	if err := service.SuperviseExitFaultQEMU(nil, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatal("missing context admitted synthetic exit:", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := service.SuperviseExitFaultQEMU(canceled, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled synthetic exit admission proceeded:", err)
	}
	service.gate <- struct{}{}
	err := service.SuperviseExitFaultQEMU(context.Background(), time.Second)
	<-service.gate
	if !errors.Is(err, processowner.ErrBusy) {
		t.Fatal("synthetic exit admitted a competing cycle:", err)
	}
	for _, interval := range []time.Duration{0, time.Second - 1, time.Hour + 1} {
		if err := service.SuperviseExitFaultQEMU(context.Background(), interval); !errors.Is(err, ErrInvalid) {
			t.Fatal("synthetic exit weakened interval bounds:", err)
		}
	}
	if err := service.SuperviseExitFaultQEMU(context.Background(), time.Second); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		t.Fatal("unstarted service accessed the runtime:", err)
	}
}

func TestNativePlannedExitSupervisionRefusesIneligibleLifetimesBeforeRuntime(t *testing.T) {
	// Negative-only lifetimes; there is no valid backend/process to signal.
	for _, service := range []*NativePlannedServiceQEMU{
		{closed: true}, {review: true}, {started: true, stopped: true},
		{started: true}, {started: true, dataVerified: true},
		{started: true, dataVerified: true, heldAttempted: true},
	} {
		service.gate = make(chan struct{}, 1)
		if err := service.SuperviseExitFaultQEMU(context.Background(), time.Second); !errors.Is(err, runtimebundle.ErrReviewRequired) {
			t.Fatal("ineligible synthetic exit reached an absent runtime:", err)
		}
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
	} else if ObserveNativePlannedDataCostsQEMU(err).Present {
		t.Fatal("unadmitted operation invented coordinator timing")
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
