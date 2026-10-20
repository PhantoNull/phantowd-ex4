//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package runtimebundle

import (
	"os"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNFSSourceKernelReadyCancelSelectorRequiresUnmixedDisposableInit(t *testing.T) {
	base := "phantowd_nfs_code_fixture=1 phantowd_nfs_source_fixture=1 init=/usr/sbin/phantowd-nfs-kernel-ready-cancel-init"
	if selected, valid := KernelReadyCancelSelectorQEMU([]byte(base)); !selected || !valid {
		t.Fatal("dedicated profile refused")
	}
	for _, value := range []string{base + " init=/init", base + "\x00", strings.Repeat("x", 4097),
		base + " phantowd_nfs_code_fixture=1", base + " phantowd_nfs_future=1",
		base + " phantowd_nfs_source_owner_rpc_start_failure_fixture=1", strings.ReplaceAll(base, "source_fixture=1", "source_fixture=0")} {
		if _, valid := KernelReadyCancelSelectorQEMU([]byte(value)); valid {
			t.Fatal("mixed or malformed profile admitted")
		}
	}
	if selected, valid := KernelReadyCancelSelectorQEMU([]byte("phantowd_nfs_code_fixture=1 init=/init")); selected || !valid {
		t.Fatal("ordinary profile changed")
	}
}

func TestNFSSourceKernelReadyCancellationDoesNotBorrowUnattachedOrNormalStoppedRoute(t *testing.T) {
	makeBoundary := func() *nfsServerQEMU {
		o, code := &NFSSourceAccessQEMU{}, &nfsCodeLifetimeQEMU{}
		v := &nfsServerQEMU{source: o, code: code, kernel: &nfskernel.ControllerQEMU{}, kernelStartAttempted: true, kernelStartVerified: true}
		o.server, code.sourceAccess = v, o
		for i, slot := range []**nfsDaemonQEMU{&v.rpcbind, &v.mountd} {
			d := &nfsDaemonQEMU{code: code, source: o, child: &processowner.PinnedSet{}, program: &os.File{}, attempted: true, readyEvidence: true, pid: i + 2, mountd: i == 1}
			d.original = d
			*slot = d
		}
		return v
	}
	v := makeBoundary()
	if !v.kernelReadyStartBoundaryQEMU() || !v.kernelReadyReviewRouteQEMU() || v.kernelBindReviewRouteQEMU() || v.partialStartStoppedProof() {
		t.Fatal("ready kernel misclassified, or bookkeeping certified settlement")
	}
	v.stopAttempted, v.reviewStopVerified = true, true
	if v.kernelReadyReviewRouteQEMU() {
		t.Fatal("normal reviewed stopped server intercepted")
	}
	v.kernelReadyStopped = true
	if !v.kernelReadyReviewRouteQEMU() || v.partialStartStoppedProof() {
		t.Fatal("dedicated route lost, or child stopped evidence omitted")
	}
	v.rpcbind.stopped, v.rpcbind.stoppedProof, v.mountd.stopped, v.mountd.stoppedProof = true, true, true, true
	if !v.partialStartStoppedProof() {
		t.Fatal("complete bookkeeping rejected before independent live witnesses")
	}
	for name, mutate := range map[string]func(*nfsServerQEMU){
		"no-original-start-success": func(v *nfsServerQEMU) { v.kernelStartVerified = false },
		"no-start-attempt":          func(v *nfsServerQEMU) { v.kernelStartAttempted = false },
		"no-kernel":                 func(v *nfsServerQEMU) { v.kernel = nil },
		"bind-frontier":             func(v *nfsServerQEMU) { v.kernelBindStopped = true },
		"exports-attempted":         func(v *nfsServerQEMU) { v.source.exportsLoaded = true },
		"running":                   func(v *nfsServerQEMU) { v.running = true },
		"io":                        func(v *nfsServerQEMU) { v.ioAttempted = true },
		"foreign-source":            func(v *nfsServerQEMU) { v.source.server = &nfsServerQEMU{} },
		"foreign-code":              func(v *nfsServerQEMU) { v.mountd.code = &nfsCodeLifetimeQEMU{} },
		"wrong-role":                func(v *nfsServerQEMU) { v.mountd.mountd = false },
		"unready":                   func(v *nfsServerQEMU) { v.mountd.readyEvidence = false },
		"uncertain-child":           func(v *nfsServerQEMU) { v.rpcbind.review = true },
		"constructor-refused":       func(v *nfsServerQEMU) { v.kernelConstructionRefused = true },
		"rpc-only":                  func(v *nfsServerQEMU) { v.rpcOnlyStartRefused = true },
	} {
		t.Run(name, func(t *testing.T) {
			v := makeBoundary()
			mutate(v)
			if v.kernelReadyStartBoundaryQEMU() || v.kernelReadyReviewRouteQEMU() || v.partialStartStoppedProof() {
				t.Fatal("unacquired or mixed graph admitted")
			}
		})
	}
}
