//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

// A model of constructor-error retention, not an uncertain real close.
type nfsCaptureReviewQEMU struct {
	constructionreview.Marker
	lease *mountowner.MountedVolumeSetLease
	cause error
}

func (*nfsCaptureReviewQEMU) Error() string   { return "QEMU retained construction model" }
func (r *nfsCaptureReviewQEMU) Unwrap() error { return r.cause }

// Called only inside the existing fixed disposable mounted-volume fixture,
// outside planner callbacks. No directory capture or server/kernel operation.
func exerciseQEMUNFSSourcePrerequisites(ctx context.Context, candidate fileserviceplan.NFSv3Candidate, set *mountowner.MountedVolumeSet) (result error) {
	lease, _, err := set.Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lease.Close()) }()
	evidence, err := lease.Verify()
	if err != nil {
		return err
	}
	storage, err := fileserviceplan.StorageFromMountedOwnerSet(evidence)
	if err != nil || !candidate.FreshAgainstStorage(storage) {
		return errors.New("NFS candidate did not match its original mounted roster")
	}
	changed := storage
	changed.OwnerFingerprint[0] ^= 1
	if candidate.FreshAgainstStorage(changed) {
		return errors.New("NFS storage comparison ignored the original roster fingerprint")
	}
	cause := errors.New("QEMU constructor model cause")
	handle := &nfsCaptureReviewQEMU{lease: lease, cause: cause}
	wrapped := fmt.Errorf("QEMU model: %w", handle)
	called := false
	got, retained := constructionreview.Rollback(wrapped, func() error { called = true; return nil })
	if got != wrapped || !retained || called || !constructionreview.Contains(got) || !errors.Is(got, cause) || handle.lease != lease {
		return errors.New("NFS constructor model lost original retention or invoked cleanup")
	}
	if _, err := handle.lease.Verify(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_PREREQUISITES_READY original_roster=true fresh_storage=true changed_owner_refused=true constructor_review=model cleanup_not_called=true lease_retained=true root_capture=false kernel_backend=false activation=false scope=disposable-qemu-only")
	return nil
}
