//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// This fixture models retained resources, NOT kernel/export/RPC qualification.
type domain struct {
	bound                   fileserviceplan.Freshness
	retained, running       bool
	starts, stops, releases int
	startError              error
	stopError               error
	stoppedError            error
	releaseError            error
	startHook               func(context.Context)
	readyHook               func(context.Context)
	stopContextError        error
}

func (d *domain) CheckInputs(_ context.Context, c fileserviceplan.NFSv3Candidate) error {
	if !d.retained || !c.FreshAgainst(d.bound) {
		return errors.New("fixture input changed")
	}
	return nil
}
func (d *domain) VerifyStopped(context.Context) error {
	if d.running {
		return errors.New("fixture still running")
	}
	return d.stoppedError
}
func (d *domain) Start(ctx context.Context) error {
	d.running = true
	d.starts++
	if d.startHook != nil {
		d.startHook(ctx)
	}
	return d.startError
}
func (d *domain) VerifyReady(ctx context.Context) error {
	if d.readyHook != nil {
		d.readyHook(ctx)
	}
	if !d.running {
		return errors.New("fixture not ready")
	}
	return nil
}
func (d *domain) Stop(ctx context.Context) error {
	d.stopContextError = ctx.Err()
	d.running = false
	d.stops++
	return d.stopError
}
func (d *domain) Release(context.Context) error {
	if d.running || !d.retained {
		return errors.New("fixture cannot release")
	}
	d.releases++
	if d.releaseError != nil {
		return d.releaseError
	}
	d.retained = false
	return nil
}

func fixture(t *testing.T, enabled bool) (fileserviceplan.NFSv3Candidate, *domain) {
	t.Helper()
	registry, err := serviceaccounts.New(1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-2222-3333-4444-555555555555"
	shares := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: uuid}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}}
	nfs := nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}}
	if enabled {
		nfs.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}
	}
	plan, err := fileserviceplan.Build(fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1, Shares: shares, NFS: nfs}, 0,
		fileserviceplan.IdentitySnapshot{Complete: true, Generation: 1, Fingerprint: sha256.Sum256([]byte("synthetic-nfs-identity")), Registry: registry, UnixUIDs: []uint32{1000}, UnixGIDs: []uint32{1000}, Samba: []fileserviceplan.SambaIdentity{}},
		fileserviceplan.StorageSnapshot{Complete: true, Generation: 1, Volumes: []fileserviceplan.ObservedVolume{{VolumeID: "bulk", FilesystemUUID: uuid, MountPath: shareconfig.VolumeMountRoot + "/bulk", Compatibility: fileserviceplan.CompatibilityQualified, MountID: 73, DeviceMajor: 9, DeviceMinor: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	return candidate, &domain{bound: plan.Freshness(), retained: true}
}

func TestOwnerStartsOnceRetainsInputsUntilVerifiedStop(t *testing.T) {
	candidate, backend := fixture(t, true)
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := o.Start(ctx); err != nil {
		t.Fatal("enabled NFS lifetime did not start:", err)
	}
	if state, err := o.Observe(); err != nil || state != nfsowner.Running || !backend.running || !backend.retained {
		t.Fatal("running lifetime lost original inputs", state, err)
	}
	if err := o.Start(ctx); !errors.Is(err, nfsowner.ErrState) || backend.starts != 1 {
		t.Fatal("duplicate startup was admitted", err)
	}
	if err := o.Stop(ctx); err != nil || backend.running || !backend.retained {
		t.Fatal("stop released retained inputs prematurely", err)
	}
	if err := o.Start(ctx); !errors.Is(err, nfsowner.ErrState) {
		t.Fatal("stopped instance restarted", err)
	}
	if err := o.Close(ctx); err != nil || backend.retained || backend.releases != 1 || backend.stops != 1 {
		t.Fatal("normal closure failed", err)
	}
	if err := o.Close(ctx); err != nil || backend.releases != 1 {
		t.Fatal("closed lifetime repeated release", err)
	}
}

func TestOwnerSharedARMFixtureExercisesSixMemoryOnlyLifetimes(t *testing.T) {
	if err := nfsowner.ExerciseQEMU(); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerDisabledPolicyNeverStartsOrStopsServer(t *testing.T) {
	candidate, backend := fixture(t, false)
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Start(context.Background()); err != nil {
		t.Fatal(err)
	}
	if backend.running || backend.starts != 0 || !backend.retained {
		t.Fatal("disabled policy started a server or lost its bound inputs")
	}
	if err := o.Close(context.Background()); err != nil || backend.stops != 0 || backend.retained {
		t.Fatal("disabled policy stopped a foreign server or failed closure", err)
	}
}

func TestOwnerPartialStartupKeepsReviewAndInputsAfterCompensation(t *testing.T) {
	candidate, backend := fixture(t, true)
	backend.startError = errors.New("private fixture pathname and identity")
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := o.Start(ctx); !errors.Is(err, nfsowner.ErrReviewRequired) || strings.Contains(err.Error(), "private") {
		t.Fatal("partial startup did not return redacted review", err)
	}
	if backend.running || backend.stops != 1 || !backend.retained {
		t.Fatal("startup compensation lost ownership or did not settle")
	}
	backend.startError = nil
	if err := o.Start(ctx); !errors.Is(err, nfsowner.ErrReviewRequired) || backend.starts != 1 {
		t.Fatal("restoration revived reviewed owner", err)
	}
	if err := o.Close(ctx); !errors.Is(err, nfsowner.ErrReviewRequired) || !backend.retained || backend.stops != 1 || backend.releases != 0 {
		t.Fatal("review released inputs or repeated compensation", err)
	}
}

func TestOwnerUncertainStopOrReleaseCannotBeRetried(t *testing.T) {
	for _, failure := range []string{"stop", "stopped-proof", "release"} {
		t.Run(failure, func(t *testing.T) {
			candidate, backend := fixture(t, true)
			o, err := nfsowner.NewQEMU(candidate, backend)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := o.Start(ctx); err != nil {
				t.Fatal(err)
			}
			private := errors.New("private failure")
			switch failure {
			case "stop":
				backend.stopError = private
			case "stopped-proof":
				backend.stoppedError = private
			case "release":
				backend.releaseError = private
			}
			if err := o.Close(ctx); !errors.Is(err, nfsowner.ErrReviewRequired) || strings.Contains(err.Error(), "private") {
				t.Fatal("uncertainty did not latch redacted review", err)
			}
			backend.stopError, backend.stoppedError, backend.releaseError = nil, nil, nil
			stops, releases := backend.stops, backend.releases
			for _, op := range []func(context.Context) error{o.Start, o.Stop, o.Close} {
				if err := op(ctx); !errors.Is(err, nfsowner.ErrReviewRequired) {
					t.Fatal("restoration erased review", err)
				}
			}
			if !backend.retained || backend.stops != stops || backend.releases != releases {
				t.Fatal("uncertain closure retried callbacks or released retained inputs")
			}
		})
	}
}

func TestOwnerLateCancellationDoesNotPublishRunningAndStillStops(t *testing.T) {
	candidate, backend := fixture(t, true)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	backend.startHook = func(context.Context) { cancel() }
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	err = o.Start(ctx)
	if !errors.Is(err, context.Canceled) || !errors.Is(err, nfsowner.ErrReviewRequired) {
		t.Fatal("late successful callback ignored cancellation", err)
	}
	if state, _ := o.Observe(); state == nfsowner.Running || backend.running || backend.stops != 1 || backend.stopContextError != nil || !backend.retained {
		t.Fatal("cancellation published running, suppressed cleanup, or released inputs", state)
	}
}

func TestOwnerRejectsCopiedNilAndSerializableLifetimes(t *testing.T) {
	candidate, backend := fixture(t, true)
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	copied := *o
	if err := copied.Close(context.Background()); !errors.Is(err, nfsowner.ErrInvalid) || !backend.retained {
		t.Fatal("copied handle consumed original lifetime", err)
	}
	if _, err := json.Marshal(o); err == nil {
		t.Fatal("NFS lifetime serialized")
	}
	if got := fmt.Sprintf("%#v", *o); got != "nfs-owner{private}" {
		t.Fatal("value formatting exposed private lifetime")
	}
	var absent *nfsowner.Owner
	if _, err := absent.Observe(); !errors.Is(err, nfsowner.ErrInvalid) {
		t.Fatal("nil owner accepted", err)
	}
	var typedNil *domain
	if got, err := nfsowner.NewQEMU(candidate, typedNil); !errors.Is(err, nfsowner.ErrInvalid) || got != nil {
		t.Fatal("typed nil backend accepted", err)
	}
	if got, err := nfsowner.NewQEMU(fileserviceplan.NFSv3Candidate{}, backend); !errors.Is(err, nfsowner.ErrInvalid) || got != nil {
		t.Fatal("missing candidate became a disabled owner", err)
	}
}

func TestOwnerSerializesCompleteTransitions(t *testing.T) {
	candidate, backend := fixture(t, true)
	entered, resume := make(chan struct{}), make(chan struct{})
	backend.startHook = func(context.Context) { close(entered); <-resume }
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- o.Start(context.Background()) }()
	<-entered
	defer func() {
		close(resume)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	if _, err := o.Observe(); !errors.Is(err, nfsowner.ErrBusy) {
		t.Fatal("observation raced a partial transition", err)
	}
	for _, operation := range []func(context.Context) error{o.Start, o.Stop, o.Close} {
		if err := operation(context.Background()); !errors.Is(err, nfsowner.ErrBusy) {
			t.Fatal("concurrent transition was admitted", err)
		}
	}
}

func TestOwnerDriftAndUnexpectedExitStopWithoutRevival(t *testing.T) {
	for _, failure := range []string{"input-drift", "unexpected-exit"} {
		t.Run(failure, func(t *testing.T) {
			candidate, backend := fixture(t, true)
			o, err := nfsowner.NewQEMU(candidate, backend)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if err := o.Start(ctx); err != nil {
				t.Fatal(err)
			}
			original := backend.bound
			if failure == "input-drift" {
				backend.bound.StorageGeneration++
			} else {
				backend.running = false
			}
			if err := o.Check(ctx); !errors.Is(err, nfsowner.ErrReviewRequired) {
				t.Fatal("live fault did not revoke ready lifetime", err)
			}
			if state, _ := o.Observe(); state != nfsowner.ReviewRequired || backend.running || backend.stops != 1 || !backend.retained {
				t.Fatal("fault did not settle while retaining review", state)
			}
			backend.bound = original
			if err := o.Check(ctx); !errors.Is(err, nfsowner.ErrReviewRequired) || backend.stops != 1 {
				t.Fatal("restored source revived/retried owner", err)
			}
		})
	}
}

func TestOwnerCanceledAdmissionHasNoEffectAndDoesNotPoison(t *testing.T) {
	candidate, backend := fixture(t, true)
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, op := range []func(context.Context) error{o.Start, o.Check, o.Stop, o.Close} {
		if !errors.Is(op(ctx), context.Canceled) {
			t.Fatal("canceled operation was admitted")
		}
	}
	if backend.starts != 0 || backend.stops != 0 || backend.releases != 0 || !backend.retained {
		t.Fatal("pre-admission cancellation touched the domain")
	}
	if err := o.Start(context.Background()); err != nil {
		t.Fatal("pre-admission refusal poisoned the lifetime", err)
	}
	if err := o.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOwnerRefusesForeignResourcesWithoutStoppingThem(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		candidate, backend := fixture(t, enabled)
		backend.running = true // not started by this Owner
		o, err := nfsowner.NewQEMU(candidate, backend)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Start(context.Background()); !errors.Is(err, nfsowner.ErrReviewRequired) {
			t.Fatal("existing domain was adopted", err)
		}
		if !backend.running || backend.starts != 0 || backend.stops != 0 || backend.releases != 0 || !backend.retained {
			t.Fatal("foreign domain was mutated")
		}
	}
}

func TestOwnerLateDeadlineAndPostReadyDriftWithholdPublication(t *testing.T) {
	for _, failure := range []string{"deadline", "post-ready-drift"} {
		t.Run(failure, func(t *testing.T) {
			candidate, backend := fixture(t, true)
			o, err := nfsowner.NewQEMU(candidate, backend)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			if failure == "deadline" {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, 50*time.Millisecond)
				defer cancel()
				backend.startHook = func(ctx context.Context) { <-ctx.Done() }
			} else {
				backend.readyHook = func(context.Context) { backend.bound.IdentityGeneration++ }
			}
			err = o.Start(ctx)
			if !errors.Is(err, nfsowner.ErrReviewRequired) || (failure == "deadline" && !errors.Is(err, context.DeadlineExceeded)) {
				t.Fatal("late result became running", err)
			}
			if state, _ := o.Observe(); state != nfsowner.ReviewRequired || backend.running || backend.stops != 1 || backend.stopContextError != nil || !backend.retained {
				t.Fatal("late outcome lost bounded independent settlement", state)
			}
		})
	}
}

func TestOwnerHealthyChecksAndUnstartedClosure(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		candidate, backend := fixture(t, enabled)
		o, err := nfsowner.NewQEMU(candidate, backend)
		if err != nil {
			t.Fatal(err)
		}
		if err := o.Start(context.Background()); err != nil {
			t.Fatal(err)
		}
		if err := o.Check(context.Background()); err != nil {
			t.Fatal("healthy fixed lifetime rejected", err)
		}
		if err := o.Close(context.Background()); err != nil {
			t.Fatal(err)
		}
		if state, err := o.Observe(); err != nil || state != nfsowner.Closed {
			t.Fatal("closure not recorded", state, err)
		}
		if err := o.Check(context.Background()); !errors.Is(err, nfsowner.ErrState) {
			t.Fatal("closed owner was checked as live", err)
		}
	}
	candidate, backend := fixture(t, true)
	o, err := nfsowner.NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Close(context.Background()); err != nil || backend.starts != 0 || backend.stops != 0 || backend.retained {
		t.Fatal("unstarted closure mutated kernel state", err)
	}
}
