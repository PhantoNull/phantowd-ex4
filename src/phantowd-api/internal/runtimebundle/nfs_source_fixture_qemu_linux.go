//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

type nfsSourceInputFixtureQEMU struct {
	pair    [2]*NFSInputsQEMU
	callers [3]*os.File
	cause   error
}

// Explicit VM-disposal fixture only: keep original uncertain construction and
// all references until process exit. This is not product quarantine/recovery.
var nfsSourceInputFixtureRetainedQEMU *nfsSourceInputFixtureQEMU

// PrepareNFSSourceInputPairQEMU stages fresh bounded RAM inputs for the NORMAL
// and FAULT lifetimes in the dedicated source guest. It returns opaque original
// handles only, never descriptors. No process/kernel/server starts here.
func PrepareNFSSourceInputPairQEMU(ctx context.Context, expected []byte, candidate fileserviceplan.NFSv3Candidate) (_ [2]*NFSInputsQEMU, result error) {
	if ctx == nil || nfsCodeGuardQEMU() != nil || nfsSourceInputFixtureRetainedQEMU != nil {
		return [2]*NFSInputsQEMU{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return [2]*NFSInputsQEMU{}, err
	}
	command, err := os.ReadFile("/proc/cmdline")
	selectors := 0
	for _, word := range strings.Fields(string(command)) {
		if word == "phantowd_nfs_source_fixture=1" {
			selectors++
		}
	}
	if err != nil || len(command) > 4096 || selectors != 1 {
		return [2]*NFSInputsQEMU{}, ErrInvalid
	}
	plan, err := NFSExpectedPlanQEMU(expected)
	if err != nil || plan.bytes > 8<<20 {
		return [2]*NFSInputsQEMU{}, ErrInvalid
	}
	f := &nfsSourceInputFixtureQEMU{}
	nfsSourceInputFixtureRetainedQEMU = f
	defer func() { f.cause = result }()
	if err := stageNFSCodeQEMU(ctx, plan); err != nil {
		return [2]*NFSInputsQEMU{}, err
	}
	if err := stageNFSInputsQEMU(candidate); err != nil {
		return [2]*NFSInputsQEMU{}, err
	}
	for i, path := range []string{nfsCodeViewQEMU, nfsConfigViewQEMU, nfsStateViewQEMU} {
		f.callers[i], err = nfsInputCallerQEMU(path)
		if err != nil {
			return [2]*NFSInputsQEMU{}, err
		}
	}
	for i := range f.pair {
		f.pair[i], err = NewNFSInputsQEMU(ctx, expected, candidate, f.callers[0], f.callers[1], f.callers[2])
		if err != nil {
			return [2]*NFSInputsQEMU{}, err // Keep ORIGINAL error, no cleanup/retry.
		}
	}
	for i, caller := range f.callers {
		if err := caller.Close(); err != nil {
			return [2]*NFSInputsQEMU{}, err // Uncertain close retains original object.
		}
		f.callers[i] = nil
	}
	if err := f.pair[0].Check(ctx); err != nil {
		return [2]*NFSInputsQEMU{}, err
	}
	if err := f.pair[1].Check(ctx); err != nil {
		return [2]*NFSInputsQEMU{}, err
	}
	fmt.Printf("PHANTOWD_NFS_SOURCE_COUNTS files=%d aliases=%d bytes=%d\n", len(plan.files), len(plan.aliases), plan.bytes)
	return f.pair, nil
}
