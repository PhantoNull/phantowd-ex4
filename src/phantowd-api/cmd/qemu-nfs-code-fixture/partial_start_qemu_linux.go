//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// Original independently prepared controller survives any fixture error.
// No stop, close, release or global-reset operation targets this controller.
var partialStartOriginalController *nfskernel.ControllerQEMU

func runSourceOwnerPartialStart(ctx context.Context, joined *nfsowner.SourceRuntimeQEMU, authority *sourcePolicyFixture,
	roots *nfsowner.ExportRootsQEMU, inputs *runtimebundle.NFSInputsQEMU, lease *mountowner.MountedVolumeSetLease, fault sourceOwnerFault) (result error) {
	phase := "owner-construction"
	defer func() {
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_OWNER_PARTIAL_START_FAILURE phase=%s\n", phase)
		}
	}()
	owner, err := joined.NewServerOwnerFixtureQEMU(ctx)
	if err != nil {
		return err
	}
	if fault == ownerKernelBindRefusal {
		phase = "independent-bound-socket"
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err != nil {
			return err
		}
		kernelSocketFixtureRetained.foreign = os.NewFile(uintptr(fd), "nfs-source-independent-bound-socket")
		if err := unix.Bind(fd, &unix.SockaddrInet4{Port: 2049, Addr: [4]byte{127, 0, 0, 1}}); err != nil {
			return err
		}
		fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_KERNEL_BIND_ARMED original_owner=true original_claims=true independent_bound_socket=true foreign_listening=false product=false scope=qemu-only")
	}
	foreign := kernelSocketForeignObservation{}
	if fault == ownerKernelBindRefusal {
		foreign, err = observeKernelSocketForeign(kernelSocketFixtureRetained.foreign)
		if err != nil {
			return err
		}
	}
	if fault == ownerKernelConstructRefusal {
		phase = "original-controller-reservation"
		partialStartOriginalController, err = nfskernel.OpenCodeQEMU(ctx)
		if err != nil {
			return err
		}
		if err := partialStartOriginalController.CheckPreparedQEMU(ctx); err != nil {
			return err
		}
		fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_KERNEL_REFUSAL_ARMED original_prepared_controller=true original_reservation=true replacement=false kernel_started=false product=false scope=qemu-only")
	}
	phase = "owner-start"
	err = owner.Start(ctx)
	if !errors.Is(err, nfsowner.ErrReviewRequired) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return errors.Join(errors.New("partial startup did not retain review"), err)
	}
	phase = "stopped-retained"
	if err := joined.VerifyServerStoppedRetainedFixtureQEMU(ctx); err != nil {
		return err
	}
	retained, err := sourceFDCount()
	if err != nil {
		return err
	}
	state, err := owner.Observe()
	if err != nil || state != nfsowner.ReviewRequired {
		return errors.New("partial startup lost review")
	}
	for _, operation := range []func(context.Context) error{owner.Start, owner.Check, owner.Stop, owner.Close, owner.ExerciseSourceIOFixtureQEMU,
		func(ctx context.Context) error { return owner.Supervise(ctx, time.Second) }} {
		if !errors.Is(operation(ctx), nfsowner.ErrReviewRequired) {
			return errors.New("partial startup admitted retry/restart/release")
		}
	}
	phase = "original-authority-retained"
	if !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.Close(), nfsowner.ErrReviewRequired) ||
		!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs.Close(), processowner.ErrBusy) ||
		!errors.Is(lease.Close(), mountowner.ErrBusy) || !errors.Is(authority.policyOwner.Close(), naspolicystore.ErrBusy) ||
		!errors.Is(authority.identity.Close(), identityowner.ErrBusy) || authority.policy.Verify(ctx) != nil ||
		authority.identityRef.Verify(ctx) != nil || !errors.Is(inputs.Check(ctx), runtimebundle.ErrReviewRequired) ||
		joined.VerifyServerStoppedRetainedFixtureQEMU(ctx) != nil {
		return errors.New("partial startup lost authority or stopped proof")
	}
	if after, err := sourceFDCount(); err != nil || after != retained {
		return errors.New("partial startup released original references")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if fault == ownerKernelBindRefusal {
		phase = "independent-socket-unchanged"
		if after, err := observeKernelSocketForeign(kernelSocketFixtureRetained.foreign); err != nil || after != foreign {
			return errors.New("independent bound socket changed during owned compensation")
		}
		fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_KERNEL_BIND_READY owned_unattached_socket_closed=true original_daemons_stopped=true exports_never_activated=true original_stopped_observation=true original_claims_retained=true source_refs_retained=true independent_socket_unchanged=true review_retained=true no_retry=true no_restart=true release=false product=false scope=qemu-only")
		return nil
	}
	if fault == ownerKernelConstructRefusal {
		phase = "original-controller-still-prepared"
		if err := partialStartOriginalController.CheckPreparedQEMU(ctx); err != nil {
			return err
		}
		if after, err := sourceFDCount(); err != nil || after != retained {
			return errors.New("prepared observation changed retained descriptor count")
		}
		fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_KERNEL_REFUSAL_READY original_daemons_stopped=true kernel_never_started=true exports_never_activated=true original_controller_prepared=true original_controller_retained=true original_reservation=true foreign_stop=false original_stopped_observation=true review_retained=true source_refs_retained=true no_retry=true no_restart=true release=false product=false scope=qemu-only")
		return nil
	}
	fmt.Println("PHANTOWD_NFS_SOURCE_OWNER_PARTIAL_START_READY rpcbind_stopped=true mountd_never_started=true kernel_never_started=true exports_never_activated=true original_stopped_observation=true review_retained=true source_refs_retained=true no_retry=true no_restart=true release=false product=false scope=qemu-only")
	return nil
}
