//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

func main() {
	if len(os.Args) == 2 && os.Args[1] == "--loader-observer" {
		if observeLoader() != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_LOADER_CHILD_FAILED")
			os.Exit(1)
		}
		return
	}
	sourceFixture := len(os.Args) == 2 && os.Args[1] == "--source-binding"
	kernelSocket := len(os.Args) == 2 && os.Args[1] == "--kernel-socket-refusal"
	kernelBind := len(os.Args) == 2 && os.Args[1] == "--source-owner-kernel-bind-refusal"
	sourceLoss := len(os.Args) == 2 && os.Args[1] == "--source-loss"
	daemonLoss := len(os.Args) == 2 && os.Args[1] == "--source-daemon-loss"
	policyLoss := len(os.Args) == 2 && os.Args[1] == "--source-owner-policy-loss"
	partialStart := len(os.Args) == 2 && os.Args[1] == "--source-owner-partial-start"
	kernelRefusal := len(os.Args) == 2 && os.Args[1] == "--source-owner-kernel-refusal"
	ownerStopLoss := len(os.Args) == 2 && os.Args[1] == "--source-owner-daemon-stop-loss"
	ownerDaemonLoss := len(os.Args) == 2 && os.Args[1] == "--source-owner-daemon-loss" || ownerStopLoss
	if (!sourceFixture && !sourceLoss && !daemonLoss && !policyLoss && !ownerDaemonLoss && !partialStart && !kernelRefusal && !kernelSocket && !kernelBind && len(os.Args) != 1) || runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		os.Exit(1)
	}
	command, commandErr := os.ReadFile("/proc/cmdline")
	selected, selectorValid := parsePolicyLossSelector(command)
	peerSelected, peerValid := parseOwnerDaemonLossSelector(command)
	stopSelected, stopValid := parseOwnerStopLossSelector(command)
	partialSelected, partialValid := parseOwnerLossSelector(command, "phantowd_nfs_source_owner_rpc_start_failure_fixture=")
	kernelSelected, kernelValid := parseOwnerLossSelector(command, "phantowd_nfs_source_owner_kernel_construct_refusal_fixture=")
	bindSelected, bindValid := parseKernelBindSelectorQEMU(command)
	if commandErr != nil || !selectorValid || selected != policyLoss || !peerValid || peerSelected != ownerDaemonLoss || !stopValid || stopSelected != ownerStopLoss || !partialValid || partialSelected != partialStart || !kernelValid || kernelSelected != kernelRefusal || !bindValid || bindSelected != kernelBind {
		os.Exit(1)
	}
	if kernelSocket {
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		if runKernelSocketRefusalQEMU(ctx, command) != nil {
			os.Exit(1)
		}
		return
	}
	file, err := os.Open("/usr/lib/phantowd/qemu-nfs-code-expected.json")
	if err != nil {
		os.Exit(1)
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil || len(data) > 128<<10 {
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	if kernelBind {
		if err := probeSourceRuntimeMode(ctx, data, false, false, ownerKernelBindRefusal); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_OWNER_KERNEL_BIND_REFUSED")
			os.Exit(1)
		}
		return
	}
	if kernelRefusal {
		if err := probeSourceRuntimeMode(ctx, data, false, false, ownerKernelConstructRefusal); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_OWNER_KERNEL_REFUSAL_REFUSED")
			os.Exit(1)
		}
		return
	}
	if partialStart {
		if err := probeSourceRuntimeMode(ctx, data, false, false, ownerRPCStartFailure); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_OWNER_PARTIAL_START_REFUSED")
			os.Exit(1)
		}
		return
	}
	if ownerDaemonLoss {
		mode := ownerScheduledDaemonLoss
		if ownerStopLoss {
			mode = ownerStopDaemonLoss
		}
		if err := probeSourceRuntimeMode(ctx, data, false, false, mode); err != nil {
			if ownerStopLoss {
				fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_OWNER_STOP_LOSS_REFUSED")
			} else {
				fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_OWNER_DAEMON_LOSS_REFUSED")
			}
			os.Exit(1)
		}
		return
	}
	if policyLoss {
		if err := probeSourceRuntimeMode(ctx, data, false, false, ownerPolicyLoss); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_OWNER_POLICY_LOSS_REFUSED")
			os.Exit(1)
		}
		return
	}
	if daemonLoss {
		if err := probeSourceDaemonLossRuntime(ctx, data); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_DAEMON_LOSS_REFUSED")
			os.Exit(1)
		}
		return
	}
	if sourceLoss {
		if err := probeSourceLossRuntime(ctx, data); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_LOSS_REFUSED")
			os.Exit(1)
		}
		return
	}
	if sourceFixture {
		if err := probeSourceRuntime(ctx, data); err != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_REFUSED")
			os.Exit(1)
		}
		return
	}
	if err := runtimebundle.ProbeNFSCodeQEMU(ctx, data); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_CODE_PROBE_REFUSED")
		os.Exit(1)
	}
}
