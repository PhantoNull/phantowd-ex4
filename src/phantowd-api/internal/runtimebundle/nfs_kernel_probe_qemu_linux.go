//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

type nfsCompanionQEMU struct {
	owner *processowner.PinnedSet
	pid   int
}

var nfsKernelUnsettledQEMU bool
var nfsKernelProbeRetainedQEMU any

// Fixed private composition only. Observations are sequential, not an atomic
// complete NFS control-domain admission or export/client quiescence census.
func nfsCompanionsLiveQEMU(ctx context.Context, s *nfsCodeLifetimeQEMU, channels *NFSMountdChannelsQEMU, companions [2]nfsCompanionQEMU) error {
	for index, companion := range companions {
		if companion.owner == nil || companion.pid <= 0 {
			return ErrInvalid
		}
		state, err := companion.owner.Observe(ctx)
		if err != nil || state.State != processowner.StateReady || state.Generation != 1 || len(state.Members) != 1 || state.Members[0].Process.PID != companion.pid || state.Members[0].Process.DiagnosticsTruncated {
			return errors.Join(ErrMismatch, err)
		}
		if ok, err := nfsRPCNullQEMU(ctx, index == 1); err != nil || !ok {
			return errors.Join(ErrMismatch, err)
		}
	}
	if companions[0].owner.CheckNFSRPCBindHandoffQEMU(ctx) != nil || companions[1].owner.CheckNFSMountdHandoffQEMU(ctx, false) != nil ||
		channels.Check(ctx) != nil || observeNFSMountdChannelsQEMU(companions[1].pid, channels) != nil || s.revalidate(ctx) != nil {
		return ErrMismatch
	}
	return nil
}

func probeNFSDKernelQEMU(ctx context.Context, s *nfsCodeLifetimeQEMU, channels *NFSMountdChannelsQEMU, companions [2]nfsCompanionQEMU) (result error) {
	if ctx == nil || s == nil || channels == nil {
		return ErrInvalid
	}
	phase := "original-inputs"
	var kernel *nfskernel.ControllerQEMU
	defer func() {
		if result != nil {
			s.review, s.cause = true, result
			nfsKernelProbeRetainedQEMU = struct {
				kernel     *nfskernel.ControllerQEMU
				companions [2]nfsCompanionQEMU
				cause      error
			}{kernel, companions, result}
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_KERNEL_FAILURE phase=%s\n", phase)
		}
	}()
	if nfsCompanionsLiveQEMU(ctx, s, channels, companions) != nil {
		return ErrMismatch
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	phase = "construct"
	kernel, err = nfskernel.OpenCodeQEMU(ctx)
	if err != nil {
		return err
	}
	copyKernel := *kernel
	if copyKernel.Start(ctx) == nil || copyKernel.CheckRunning(ctx) == nil || copyKernel.Stop(ctx) == nil || copyKernel.Close(ctx) == nil {
		return ErrMismatch
	}
	phase = "start"
	nfsKernelUnsettledQEMU = true
	if err := kernel.Start(ctx); err != nil {
		return err // Uncertain kernel retains BOTH daemons; no stop/restart retry.
	}
	phase = "ready"
	checkErr := func() error {
		if kernel.CheckRunning(ctx) != nil || nfsCompanionsLiveQEMU(ctx, s, channels, companions) != nil {
			return ErrMismatch
		}
		if ok, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || !ok {
			return errors.Join(ErrMismatch, err)
		}
		if kernel.CheckRunning(ctx) != nil || nfsCompanionsLiveQEMU(ctx, s, channels, companions) != nil {
			return ErrMismatch
		}
		return nil
	}()
	phase = "stop"
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopErr := kernel.Stop(cleanup)
	cancel()
	if stopErr != nil {
		return errors.Join(ErrReviewRequired, checkErr, stopErr)
	}
	nfsKernelUnsettledQEMU = false
	if checkErr != nil {
		phase = "ready"
		return checkErr
	}
	if nfsCompanionsLiveQEMU(ctx, s, channels, companions) != nil {
		return ErrMismatch
	}
	if ready, err := nfsFixedNullQEMU(ctx, "127.0.0.1:2049", 100003, 3); err != nil || ready {
		return errors.Join(ErrMismatch, err)
	}
	phase = "close"
	if err := kernel.Close(ctx); err != nil {
		return err
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before || s.revalidate(ctx) != nil {
		return errors.Join(ErrMismatch, err)
	}
	fmt.Println("PHANTOWD_NFS_KERNEL_READY original_control=true original_namespaces=true retained_ipv4_socket=true original_daemons_live=true null_rpc_v3=true threads=2 stop_verified=true fd_balance=true exports=false owner_backend=false product=false scope=qemu-only")
	return nil
}
