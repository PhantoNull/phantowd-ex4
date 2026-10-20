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

func TestNFSSourceRPCOnlyFailureRequiresExactUnmixedSelector(t *testing.T) {
	base := "phantowd_nfs_code_fixture=1 phantowd_nfs_source_fixture=1 "
	flag := "phantowd_nfs_source_owner_rpc_start_failure_fixture=1"
	if !nfsRPCOnlyFailureSelectorQEMU([]byte(base + flag)) {
		t.Fatal("dedicated synthetic constructor-failure profile refused")
	}
	invalid := []string{"", base, flag, base + flag + " " + flag, base + strings.ReplaceAll(flag, "=1", "=0"), strings.Repeat("x", 4097)}
	for _, other := range []string{"phantowd_nfs_code_fixture=1", "phantowd_nfs_source_fixture=0", "phantowd_nfs_source_loss_fixture=1", "phantowd_nfs_source_daemon_loss_fixture=1", "phantowd_nfs_source_owner_policy_loss_fixture=1", "phantowd_nfs_source_owner_daemon_loss_fixture=1", "phantowd_nfs_source_owner_stop_loss_fixture=1"} {
		invalid = append(invalid, base+flag+" "+other)
	}
	for _, text := range invalid {
		if nfsRPCOnlyFailureSelectorQEMU([]byte(text)) {
			t.Fatal("malformed/mixed/standalone profile accepted", text)
		}
	}
}

func TestNFSSourcePartialStartBoundaryRefusesUnacquiredAndMixedComponents(t *testing.T) {
	makeBoundary := func() *nfsServerQEMU {
		source, code := &NFSSourceAccessQEMU{}, &nfsCodeLifetimeQEMU{}
		v := &nfsServerQEMU{source: source, code: code, rpcOnlyStartRefused: true}
		source.server, code.sourceAccess = v, source
		v.rpcbind = &nfsDaemonQEMU{code: code, source: source, child: &processowner.PinnedSet{}, program: &os.File{}, attempted: true, readyEvidence: true, pid: 2}
		v.rpcbind.original = v.rpcbind
		return v
	}
	if !makeBoundary().rpcOnlyStartBoundary() {
		t.Fatal("bookkeeping frontier refused before original-reference validation")
	}
	for name, mutate := range map[string]func(*nfsServerQEMU){
		"not-established":        func(v *nfsServerQEMU) { v.rpcOnlyStartRefused = false },
		"no-rpc":                 func(v *nfsServerQEMU) { v.rpcbind = nil },
		"mountd-acquired":        func(v *nfsServerQEMU) { v.mountd = &nfsDaemonQEMU{} },
		"kernel-acquired":        func(v *nfsServerQEMU) { v.kernel = &nfskernel.ControllerQEMU{} },
		"kernel-start-attempted": func(v *nfsServerQEMU) { v.kernelStartAttempted = true },
		"server-running":         func(v *nfsServerQEMU) { v.running = true },
		"io-attempted":           func(v *nfsServerQEMU) { v.ioAttempted = true },
		"exports":                func(v *nfsServerQEMU) { v.source.exportsLoaded = true },
		"wrong-original":         func(v *nfsServerQEMU) { v.source.server = &nfsServerQEMU{} },
		"wrong-code":             func(v *nfsServerQEMU) { v.rpcbind.code = &nfsCodeLifetimeQEMU{} },
		"wrong-source":           func(v *nfsServerQEMU) { v.rpcbind.source = &NFSSourceAccessQEMU{} },
		"never-started":          func(v *nfsServerQEMU) { v.rpcbind.attempted = false },
		"not-ready":              func(v *nfsServerQEMU) { v.rpcbind.readyEvidence = false },
		"unknown-rpc":            func(v *nfsServerQEMU) { v.rpcbind.review = true },
		"wrong-role":             func(v *nfsServerQEMU) { v.rpcbind.mountd = true },
		"closed-rpc":             func(v *nfsServerQEMU) { v.rpcbind.closed = true },
	} {
		t.Run(name, func(t *testing.T) {
			v := makeBoundary()
			mutate(v)
			if v.rpcOnlyStartBoundary() {
				t.Fatal("mixed or unacquired frontier accepted")
			}
		})
	}
}

func TestNFSSourcePartialDaemonBoundaryRequiresOriginalAcquisitionAndNoKernelStart(t *testing.T) {
	makeBoundary := func() *nfsServerQEMU {
		source, code := &NFSSourceAccessQEMU{}, &nfsCodeLifetimeQEMU{}
		v := &nfsServerQEMU{source: source, code: code, kernelConstructionRefused: true}
		source.server, code.sourceAccess = v, source
		for index, slot := range []**nfsDaemonQEMU{&v.rpcbind, &v.mountd} {
			d := &nfsDaemonQEMU{code: code, source: source, child: &processowner.PinnedSet{}, program: &os.File{}, attempted: true, readyEvidence: true, pid: index + 2, mountd: index == 1}
			d.original = d
			*slot = d
		}
		return v
	}
	if !makeBoundary().daemonsOnlyStartBoundary() {
		t.Fatal("bookkeeping frontier refused before original-reference validation")
	}
	for name, mutate := range map[string]func(*nfsServerQEMU){
		"no-constructor-refusal": func(v *nfsServerQEMU) { v.kernelConstructionRefused = false },
		"mixed-frontier":         func(v *nfsServerQEMU) { v.rpcOnlyStartRefused = true },
		"kernel-result-present":  func(v *nfsServerQEMU) { v.kernel = &nfskernel.ControllerQEMU{} },
		"kernel-start-attempted": func(v *nfsServerQEMU) { v.kernelStartAttempted = true },
		"no-mountd":              func(v *nfsServerQEMU) { v.mountd = nil },
		"no-rpcbind":             func(v *nfsServerQEMU) { v.rpcbind = nil },
		"server-running":         func(v *nfsServerQEMU) { v.running = true },
		"exports":                func(v *nfsServerQEMU) { v.source.exportsLoaded = true },
		"wrong-original":         func(v *nfsServerQEMU) { v.source.server = &nfsServerQEMU{} },
		"wrong-role":             func(v *nfsServerQEMU) { v.mountd.mountd = false },
		"wrong-source":           func(v *nfsServerQEMU) { v.mountd.source = &NFSSourceAccessQEMU{} },
		"wrong-code":             func(v *nfsServerQEMU) { v.mountd.code = &nfsCodeLifetimeQEMU{} },
		"not-ready":              func(v *nfsServerQEMU) { v.mountd.readyEvidence = false },
		"unknown-daemon":         func(v *nfsServerQEMU) { v.mountd.review = true },
		"unstarted":              func(v *nfsServerQEMU) { v.mountd.attempted = false },
		"closed":                 func(v *nfsServerQEMU) { v.mountd.closed = true },
	} {
		t.Run(name, func(t *testing.T) {
			v := makeBoundary()
			mutate(v)
			if v.daemonsOnlyStartBoundary() {
				t.Fatal("unknown or mixed acquisition frontier accepted")
			}
		})
	}
}
