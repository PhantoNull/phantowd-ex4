//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// An additional exact selector, not an alternative hardware/source guard.
// The factory/mounted-roster construction still requires the original ARMv5,
// VersatilePB and disposable source disk guards BEFORE any fault mutation.
func parsePolicyLossSelector(data []byte) (selected, valid bool) {
	return parseOwnerLossSelector(data, "phantowd_nfs_source_owner_policy_loss_fixture=")
}

// Each caller supplies one fixed internal selector. Exact source/code flags,
// one selected fault and no sibling fault are required before guest mutation.
func parseOwnerLossSelector(data []byte, faultFlag string) (selected, valid bool) {
	if len(data) > 4096 {
		return false, false
	}
	code, source, policy, other := 0, 0, 0, 0
	invalidBase := false
	for _, word := range strings.Fields(string(data)) {
		if strings.HasPrefix(word, "phantowd_nfs_code_fixture=") && word != "phantowd_nfs_code_fixture=1" ||
			strings.HasPrefix(word, "phantowd_nfs_source_fixture=") && word != "phantowd_nfs_source_fixture=1" {
			invalidBase = true
		}
		if word == "phantowd_nfs_code_fixture=1" {
			code++
		}
		if word == "phantowd_nfs_source_fixture=1" {
			source++
		}
		if strings.HasPrefix(word, faultFlag) {
			selected = true
			if word != faultFlag+"1" {
				return true, false
			}
			policy++
		}
		for _, prefix := range []string{"phantowd_nfs_source_loss_fixture=", "phantowd_nfs_source_daemon_loss_fixture=",
			"phantowd_nfs_source_owner_policy_loss_fixture=", "phantowd_nfs_source_owner_daemon_loss_fixture="} {
			if prefix != faultFlag && strings.HasPrefix(word, prefix) {
				other++
			}
		}
	}
	if !selected {
		return false, true
	}
	return true, code == 1 && source == 1 && policy == 1 && other == 0 && !invalidBase
}

func runSourceOwnerPolicyLoss(ctx context.Context, joined *nfsowner.SourceRuntimeQEMU, authority *sourcePolicyFixture,
	roots *nfsowner.ExportRootsQEMU, inputs *runtimebundle.NFSInputsQEMU, lease *mountowner.MountedVolumeSetLease) (result error) {
	phase := "owner-construction"
	defer func() {
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_OWNER_POLICY_LOSS_FAILURE phase=%s\n", phase)
		}
	}()
	owner, err := joined.NewServerOwnerFixtureQEMU(ctx)
	if err != nil {
		return err
	}
	phase = "owner-start"
	if err := owner.Start(ctx); err != nil {
		return err
	}
	phase = "source-io"
	if err := owner.ExerciseSourceIOFixtureQEMU(ctx); err != nil {
		return err
	}
	// Original controls must not certify stopped while the actual server runs.
	if joined.VerifyServerStoppedRetainedFixtureQEMU(ctx) == nil {
		return errors.New("running owner claimed stopped review")
	}
	phase = "supervisor-admission"
	loop, cancel := context.WithCancel(ctx)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- owner.Supervise(loop, time.Second) }()
	finished := false
	defer func() {
		if !finished {
			cancel()
			result = errors.Join(result, <-done)
		}
	}()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		_, err := owner.Observe()
		if errors.Is(err, nfsowner.ErrBusy) {
			break
		}
		select {
		case err := <-done:
			finished = true
			return errors.Join(errors.New("supervisor failed admission"), err)
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
	// All contenders refuse before the fault. There is no manual Check between
	// mutation and the scheduled scan; Observe does not sample policy/kernel.
	for _, operation := range []func(context.Context) error{owner.Start, owner.Check, owner.Stop, owner.Close, owner.ExerciseSourceIOFixtureQEMU,
		func(ctx context.Context) error { return owner.Supervise(ctx, time.Second) }} {
		if !errors.Is(operation(ctx), nfsowner.ErrBusy) {
			return errors.New("supervisor lost exclusivity")
		}
	}
	phase = "policy-replacement"
	restore, err := replaceFreshPolicy(authority)
	if err != nil {
		return err
	}
	phase = "periodic-refusal"
	select {
	case err = <-done:
		finished = true
	case <-ctx.Done():
		return ctx.Err()
	}
	if !errors.Is(err, nfsowner.ErrReviewRequired) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(errors.New("periodic policy refusal not observed"), err)
	}
	phase = "stopped-retained"
	if joined.VerifyServerStoppedRetainedFixtureQEMU(ctx) != nil {
		return errors.New("reviewed original server stop not verified")
	}
	retained, err := sourceFDCount()
	if err != nil {
		return err
	}
	phase = "restoration"
	if err := restore(); err != nil {
		return err
	}
	// Restoration cannot revive the SAME original Owner or free any remaining
	// source/input/claim reference. No release, retry or replacement is attempted.
	phase = "restored-refusals"
	state, err := owner.Observe()
	if err != nil || state != nfsowner.ReviewRequired {
		return errors.New("owner review lost")
	}
	for _, operation := range []func(context.Context) error{owner.Start, owner.Check, owner.Stop, owner.Close, owner.ExerciseSourceIOFixtureQEMU,
		func(ctx context.Context) error { return owner.Supervise(ctx, time.Second) }} {
		if !errors.Is(operation(ctx), nfsowner.ErrReviewRequired) {
			return errors.New("restoration revived reviewed owner")
		}
	}
	if !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.Close(), nfsowner.ErrReviewRequired) ||
		!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs.Close(), processowner.ErrBusy) ||
		!errors.Is(lease.Close(), mountowner.ErrBusy) || !errors.Is(authority.policyOwner.Close(), naspolicystore.ErrBusy) ||
		!errors.Is(authority.identity.Close(), identityowner.ErrBusy) || !errors.Is(authority.policy.Verify(ctx), naspolicystore.ErrReview) ||
		authority.identityRef.Verify(ctx) != nil || inputs.Check(ctx) != nil ||
		joined.VerifyServerStoppedRetainedFixtureQEMU(ctx) != nil {
		return errors.New("review lost original references or stopped proof")
	}
	if after, err := sourceFDCount(); err != nil || after != retained {
		return errors.New("review released original references")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_POLICY_LOSS_READY periodic_detection=true manual_detection=false exclusive=true same_bytes_replacement=true atomic_exchange=true policy_review=true kernel_stopped=true daemons_stopped=true exports_withdrawn=true original_claims_retained=true source_refs_retained=true review_retained=true restored_refused=true no_retry=true no_restart=true release=false quiescence=false product=false scope=qemu-only")
	return nil
}

// The ONLY mutation target is one fixed leaf in this process's fresh RAM
// policy role. Populate and verify the replacement OUTSIDE the watched role,
// then exchange both complete inodes atomically. The scan can never observe
// a deliberately missing/partially written policy. No product writer/path API.
func replaceFreshPolicy(f *sourcePolicyFixture) (func() error, error) {
	if f == nil || !strings.HasPrefix(f.policyDirectory, "/run/nfs-policy-owner-") || filepath.Base(f.policyDirectory) != "policy" {
		return nil, errors.New("fresh policy role required")
	}
	path := filepath.Join(f.policyDirectory, "nas-services.json")
	var original unix.Stat_t
	if unix.Lstat(path, &original) != nil || original.Mode != unix.S_IFREG|0600 || original.Uid != 0 || original.Gid != 0 ||
		original.Nlink != 1 || original.Size <= 0 || original.Size > 1<<20 {
		return nil, errors.New("original policy metadata refused")
	}
	data, err := f.readFreshPolicy()
	if err != nil || int64(len(data)) != original.Size {
		return nil, errors.Join(errors.New("bounded policy read refused"), err)
	}
	// A distinct fresh /run directory, not the policy directory or its parent.
	// Creating/writing this file does not pre-dirty the policy's watched epoch.
	stage, err := os.MkdirTemp("/run", "nfs-policy-fault-")
	if err != nil {
		return nil, err
	}
	staged := filepath.Join(stage, "replacement")
	copy, err := os.OpenFile(staged, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return nil, err
	}
	f.faultFile = copy
	n, writeErr := copy.Write(data)
	var actual []byte
	if writeErr == nil && n == len(data) {
		_, writeErr = copy.Seek(0, io.SeekStart)
		if writeErr == nil {
			actual, writeErr = io.ReadAll(io.LimitReader(copy, (1<<20)+1))
		}
	}
	var replacement, named unix.Stat_t
	statErr := unix.Fstat(int(copy.Fd()), &replacement)
	closeErr := copy.Close()
	if closeErr == nil {
		f.faultFile = nil
	}
	if writeErr != nil || closeErr != nil || n != len(data) || statErr != nil ||
		replacement.Mode != original.Mode || replacement.Uid != original.Uid || replacement.Gid != original.Gid ||
		replacement.Nlink != 1 || replacement.Dev != original.Dev || replacement.Ino == original.Ino ||
		!bytes.Equal(data, actual) || sha256.Sum256(data) != sha256.Sum256(actual) ||
		unix.Lstat(staged, &named) != nil || named.Dev != replacement.Dev || named.Ino != replacement.Ino {
		return nil, errors.Join(errors.New("complete staged replacement refused"), writeErr, closeErr, statErr)
	}
	if unix.Lstat(path, &named) != nil || named.Dev != original.Dev || named.Ino != original.Ino {
		return nil, errors.New("original binding changed before exchange")
	}
	if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, staged, unix.RENAME_EXCHANGE); err != nil {
		return nil, err
	}
	actual, err = f.readFreshPolicy()
	var saved unix.Stat_t
	if err != nil || !bytes.Equal(data, actual) || unix.Lstat(path, &named) != nil || named.Dev != replacement.Dev || named.Ino != replacement.Ino ||
		unix.Lstat(staged, &saved) != nil || saved.Dev != original.Dev || saved.Ino != original.Ino {
		return nil, errors.New("atomic same-byte replacement witness refused")
	}
	return func() error {
		var current, saved unix.Stat_t
		if unix.Lstat(path, &current) != nil || current.Dev != replacement.Dev || current.Ino != replacement.Ino ||
			unix.Lstat(staged, &saved) != nil || saved.Dev != original.Dev || saved.Ino != original.Ino {
			return errors.New("exchange bindings changed")
		}
		if err := unix.Renameat2(unix.AT_FDCWD, path, unix.AT_FDCWD, staged, unix.RENAME_EXCHANGE); err != nil {
			return err
		}
		actual, err := f.readFreshPolicy()
		var restored unix.Stat_t
		if err != nil || unix.Lstat(path, &restored) != nil || restored.Dev != original.Dev || restored.Ino != original.Ino || !bytes.Equal(data, actual) {
			return errors.New("atomic original restoration witness refused")
		}
		return nil // Replacement stays in owned guest RAM until fixture disposal.
	}, nil
}

// Fixed newly provisioned RAM leaf only. Bound before reading and retain every
// uncertain-close object through the original global fixture, never retry it.
func (f *sourcePolicyFixture) readFreshPolicy() ([]byte, error) {
	if f.faultFile != nil {
		return nil, errors.New("policy fixture retains uncertain file")
	}
	file, err := os.OpenFile(filepath.Join(f.policyDirectory, "nas-services.json"), os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f.faultFile = file
	var st unix.Stat_t
	var data []byte
	if unix.Fstat(int(file.Fd()), &st) != nil || st.Mode != unix.S_IFREG|0600 || st.Uid != 0 || st.Gid != 0 || st.Nlink != 1 || st.Size <= 0 || st.Size > 1<<20 {
		err = errors.New("policy fixture file metadata refused")
	} else {
		data, err = io.ReadAll(io.LimitReader(file, (1<<20)+1))
		if len(data) > 1<<20 || int64(len(data)) != st.Size {
			err = errors.New("policy fixture read budget refused")
		}
	}
	closeErr := file.Close()
	if closeErr == nil {
		f.faultFile = nil
	}
	if err != nil || closeErr != nil {
		return nil, errors.Join(err, closeErr)
	}
	return data, nil
}
