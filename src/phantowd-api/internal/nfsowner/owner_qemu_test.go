//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestPreparedOwnerKeepsUncertainClosureForReview(t *testing.T) {
	for _, phase := range []string{"inputs", "stopped", "release", "wrapped-cancel"} {
		t.Run(phase, func(t *testing.T) {
			candidate, backend := preparedInputs(t)
			owner, _ := NewQEMU(candidate, backend)
			backend.fail = phase
			if phase == "wrapped-cancel" {
				backend.fail, backend.cause = "inputs", context.Canceled
			}
			if err := owner.Close(context.Background()); !errors.Is(err, ErrReviewRequired) || phase == "wrapped-cancel" && err.Error() != ErrReviewRequired.Error()+"\n"+context.Canceled.Error() {
				t.Fatal("uncertain closure did not return the fixed review result", err)
			}
			backend.fail = ""
			releases := backend.releases
			if err := owner.Close(context.Background()); !errors.Is(err, ErrReviewRequired) || backend.releases != releases || !backend.retained {
				t.Fatal("restoration repeated uncertain cleanup", err)
			}
			if state, _ := owner.Observe(); state != ReviewRequired {
				t.Fatal("review was not retained", state)
			}
		})
	}
}

func preparedInputs(t *testing.T) (fileserviceplan.NFSv3Candidate, *preparedBackend) {
	return lifetimeInputs(t, false)
}

func lifetimeInputs(t *testing.T, enabled bool) (fileserviceplan.NFSv3Candidate, *preparedBackend) {
	t.Helper()
	registry, err := serviceaccounts.New(1000, 2000)
	if err != nil {
		t.Fatal(err)
	}
	const uuid = "11111111-2222-3333-4444-555555555555"
	shares := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: uuid}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
	policy := nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}}
	if enabled {
		policy.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}
	}
	plan, err := fileserviceplan.Build(fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1, Shares: shares, NFS: policy}, 0,
		fileserviceplan.IdentitySnapshot{Complete: true, Generation: 1, Fingerprint: sha256.Sum256([]byte("synthetic-nfs-identity")), Registry: registry, UnixUIDs: []uint32{1000}, UnixGIDs: []uint32{1000}, Samba: []fileserviceplan.SambaIdentity{}},
		fileserviceplan.StorageSnapshot{Complete: true, Generation: 1, Volumes: []fileserviceplan.ObservedVolume{{VolumeID: "bulk", FilesystemUUID: uuid, MountPath: shareconfig.VolumeMountRoot + "/bulk", Compatibility: fileserviceplan.CompatibilityQualified, MountID: 73, DeviceMajor: 9, DeviceMinor: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	return candidate, &preparedBackend{bound: plan.Freshness(), retained: true}
}

func TestPreparedOwnerClosesOriginalInputsOnce(t *testing.T) {
	candidate, backend := preparedInputs(t)
	owner, err := NewQEMU(candidate, backend)
	if err != nil {
		t.Fatal(err)
	}
	if state, err := owner.Observe(); err != nil || state != Prepared || !backend.retained {
		t.Fatal("construction consumed or failed to retain the prepared inputs", state, err)
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if state, err := owner.Observe(); err != nil || state != Closed || backend.retained || backend.releases != 1 {
		t.Fatal("prepared closure did not release the original inputs once", state, err)
	}
	if err := owner.Close(context.Background()); err != nil || backend.releases != 1 {
		t.Fatal("closed owner repeated release", err)
	}
}

func TestPreparedOwnerCopyCannotConsumeOriginal(t *testing.T) {
	candidate, backend := preparedInputs(t)
	owner, _ := NewQEMU(candidate, backend)
	copy := *owner
	if err := copy.Close(context.Background()); !errors.Is(err, ErrInvalid) || !backend.retained {
		t.Fatal("copied handle consumed the original prepared lifetime", err)
	}
	if _, err := copy.Observe(); !errors.Is(err, ErrInvalid) {
		t.Fatal("copied observation admitted", err)
	}
	for _, call := range []func(context.Context) error{copy.Start, copy.Stop} {
		if err := call(context.Background()); !errors.Is(err, ErrInvalid) {
			t.Fatal("copied lifecycle admitted", err)
		}
	}
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPreparedOwnerRejectsMissingCandidateAndBackend(t *testing.T) {
	candidate, backend := preparedInputs(t)
	var typedNil *preparedBackend
	for _, b := range []QEMUBackend{nil, typedNil} {
		if owner, err := NewQEMU(candidate, b); owner != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("missing backend accepted", err)
		}
	}
	if owner, err := NewQEMU(fileserviceplan.NFSv3Candidate{}, backend); owner != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("missing candidate accepted", err)
	}
	var absent *Owner
	if _, err := absent.Observe(); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil handle accepted", err)
	}
	if err := (&Owner{}).Close(context.Background()); !errors.Is(err, ErrInvalid) || backend.releases != 0 {
		t.Fatal("zero owner had effects", err)
	}
}

func TestPreparedOwnerCancellationDoesNotReleaseInputs(t *testing.T) {
	candidate, backend := preparedInputs(t)
	owner, _ := NewQEMU(candidate, backend)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := owner.Close(ctx); !errors.Is(err, context.Canceled) || !backend.retained {
		t.Fatal("canceled admission had effects", err)
	}
	if err := owner.Close(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context admitted", err)
	}
	ctx, cancel = context.WithCancel(context.Background())
	defer cancel()
	backend.hook = func(string) { cancel() }
	if err := owner.Close(ctx); !errors.Is(err, ErrReviewRequired) || !errors.Is(err, context.Canceled) || backend.releases != 0 || !backend.retained {
		t.Fatal("late cancellation published closure or released inputs", err)
	}
}

func TestPreparedOwnerSerializesWholeClosure(t *testing.T) {
	candidate, backend := preparedInputs(t)
	owner, _ := NewQEMU(candidate, backend)
	entered, resume, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	backend.hook = func(phase string) {
		if phase != "inputs" {
			return
		}
		select {
		case <-entered:
			return
		default:
			close(entered)
			<-resume
		}
	}
	go func() { done <- owner.Close(context.Background()) }()
	<-entered
	defer func() {
		close(resume)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	for _, call := range []func(context.Context) error{owner.Close, owner.Start, owner.Stop} {
		if err := call(context.Background()); !errors.Is(err, ErrBusy) {
			t.Fatal("concurrent transition admitted", err)
		}
	}
	if _, err := owner.Observe(); !errors.Is(err, ErrBusy) {
		t.Fatal("partial transition observed", err)
	}
}
