//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package runtimebundle

import (
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNFSSourceKernelBindBoundaryRequiresOriginalAcquiredUnpublishedGraph(t *testing.T) {
	makeBoundary := func() *nfsServerQEMU {
		o, code := &NFSSourceAccessQEMU{}, &nfsCodeLifetimeQEMU{}
		v := &nfsServerQEMU{source: o, code: code, kernel: &nfskernel.ControllerQEMU{}, kernelStartAttempted: true}
		o.server, code.sourceAccess = v, o
		for i, slot := range []**nfsDaemonQEMU{&v.rpcbind, &v.mountd} {
			d := &nfsDaemonQEMU{code: code, source: o, child: &processowner.PinnedSet{}, program: &os.File{}, attempted: true, readyEvidence: true, pid: i + 2, mountd: i == 1}
			d.original = d
			*slot = d
		}
		return v
	}
	if !makeBoundary().kernelBindStartBoundaryQEMU() {
		t.Fatal("bookkeeping boundary refused before independent original-resource checks")
	}
	normalStopped := makeBoundary()
	normalStopped.stopAttempted, normalStopped.reviewStopVerified = true, true
	if normalStopped.kernelBindReviewRouteQEMU() {
		t.Fatal("normal reviewed stopped server intercepted by new bind-refusal route")
	}
	normalStopped.kernelBindStopped = true
	if !normalStopped.kernelBindReviewRouteQEMU() {
		t.Fatal("known bind-refusal stopped observation lost its dedicated route")
	}
	for name, mutate := range map[string]func(*nfsServerQEMU){
		"no-kernel":      func(v *nfsServerQEMU) { v.kernel = nil },
		"not-attempted":  func(v *nfsServerQEMU) { v.kernelStartAttempted = false },
		"mixed":          func(v *nfsServerQEMU) { v.kernelConstructionRefused = true },
		"rpc-only":       func(v *nfsServerQEMU) { v.rpcOnlyStartRefused = true },
		"running":        func(v *nfsServerQEMU) { v.running = true },
		"io":             func(v *nfsServerQEMU) { v.ioAttempted = true },
		"exported":       func(v *nfsServerQEMU) { v.source.exportsLoaded = true },
		"wrong-original": func(v *nfsServerQEMU) { v.source.server = &nfsServerQEMU{} },
		"wrong-code":     func(v *nfsServerQEMU) { v.mountd.code = &nfsCodeLifetimeQEMU{} },
		"wrong-role":     func(v *nfsServerQEMU) { v.mountd.mountd = false },
		"unknown-child":  func(v *nfsServerQEMU) { v.mountd.review = true },
		"not-ready":      func(v *nfsServerQEMU) { v.rpcbind.readyEvidence = false },
	} {
		t.Run(name, func(t *testing.T) {
			v := makeBoundary()
			mutate(v)
			if v.kernelBindStartBoundaryQEMU() || v.partialStartStoppedProof() {
				t.Fatal("unacquired/mixed graph promoted")
			}
		})
	}
	if makeBoundary().partialStartStoppedProof() {
		t.Fatal("bookkeeping alone certified stopped components")
	}
}
