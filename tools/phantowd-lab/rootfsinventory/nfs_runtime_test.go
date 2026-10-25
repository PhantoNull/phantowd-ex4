// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"fmt"
	"reflect"
	"slices"
	"strings"
	"testing"
)

func nfsRuntimeReport() Report {
	r := Report{Format: "phantowd-extracted-rootfs-inventory", SchemaVersion: 1, RootDigest: strings.Repeat("b", 64)}
	for _, name := range []string{"rpcbind", "rpc.mountd", "exportfs", "rpc.nfsd", "rpc.statd", "sm-notify"} {
		file := runtimeELF("usr/sbin/"+name, "libc.so.6")
		file.ELF.Interpreter = "/lib/ld-linux.so.3"
		r.Files = append(r.Files, file)
	}
	r.Files = append(r.Files, runtimeELF("lib/libc-actual.so"), runtimeELF("lib/ld-linux.so.3"))
	r.Symlinks = []Symlink{{Path: "lib/libc.so.6", Target: "libc-actual.so"}}
	return r
}

func TestNFSRuntimeClosureUnifiesSixEntriesWithoutAuthorizingExecution(t *testing.T) {
	r := nfsRuntimeReport()
	got := r.NFSRuntimeClosure()
	if !got.StaticDependenciesResolved || got.RuntimeQualified || got.ExecutionAuthorized || len(got.ExpectedEntries) != 6 || len(got.Objects) != 8 || got.TotalBytes != 800 || got.RootDigest != r.RootDigest {
		t.Fatal("incomplete or authorized NFS userspace candidate", got)
	}
	if !reflect.DeepEqual(got.Objects[1].Bindings, []string{"lib/libc-actual.so", "lib/libc.so.6"}) {
		t.Fatal("shared library lost its canonical path or requested alias")
	}
	for _, name := range []string{"rpcbind", "rpc.mountd", "exportfs", "rpc.nfsd", "rpc.statd", "sm-notify"} {
		if !slices.Contains(got.ExpectedEntries, "usr/sbin/"+name) {
			t.Fatal("missing fixed NFS userspace entry", name)
		}
	}
	slices.Reverse(r.Files)
	if !reflect.DeepEqual(got, r.NFSRuntimeClosure()) {
		t.Fatal("inventory order changed the complete candidate")
	}
}

func TestNFSRuntimeClosureRejectsEveryMissingEntryWithoutPartialObjects(t *testing.T) {
	for index := range 6 {
		r := nfsRuntimeReport()
		missing := r.Files[index].Path
		r.Files = append(r.Files[:index], r.Files[index+1:]...)
		got := r.NFSRuntimeClosure()
		if got.StaticDependenciesResolved || got.RuntimeQualified || got.ExecutionAuthorized || got.TotalBytes != 0 || len(got.Objects) != 0 || got.FailedEntry != missing || got.Reason == "" {
			t.Fatal("partial six-entry candidate escaped", missing, got)
		}
	}
}

func TestNFSRuntimeClosureRefusesInvalidProfileAndDetachedOutputs(t *testing.T) {
	for _, fault := range []string{"digest", "duplicate", "interpreter", "header"} {
		r := nfsRuntimeReport()
		switch fault {
		case "digest":
			r.RootDigest = "invalid-not-a-root-digest"
		case "duplicate":
			r.Files = append(r.Files, r.Files[5])
		case "interpreter":
			r.Files[5].ELF.Interpreter = ""
		case "header":
			r.Files[5].ELF.HeaderFlags = nil
		}
		got := r.NFSRuntimeClosure()
		if got.StaticDependenciesResolved || got.RuntimeQualified || got.ExecutionAuthorized || got.TotalBytes != 0 || len(got.Objects) != 0 || got.Reason == "" || fault == "digest" && got.RootDigest != "" {
			t.Fatal("invalid profile yielded partial or authorized evidence", fault, got)
		}
	}
	r := nfsRuntimeReport()
	got := r.NFSRuntimeClosure()
	got.ExpectedEntries[0], got.Objects[0].Bindings[0] = "changed", "changed"
	again := r.NFSRuntimeClosure()
	if !again.StaticDependenciesResolved || again.ExpectedEntries[0] == "changed" || again.Objects[0].Bindings[0] == "changed" {
		t.Fatal("returned candidate shared mutable policy")
	}
}

func TestNFSRuntimeClosureBoundsTheUnionNotEachEntrySeparately(t *testing.T) {
	for _, budget := range []string{"bytes", "objects", "bindings"} {
		r := nfsRuntimeReport()
		for index := range 6 {
			if budget == "bytes" {
				r.Files[index].Size = 12 * 1024 * 1024
				continue
			}
			count := 50
			if budget == "bindings" {
				count = 180
			}
			for item := range count {
				name := fmt.Sprintf("libnfs-%d-%d.so", index, item)
				r.Files[index].ELF.Needed = append(r.Files[index].ELF.Needed, name)
				if budget == "objects" {
					r.Files = append(r.Files, runtimeELF("lib/"+name))
				} else {
					r.Symlinks = append(r.Symlinks, Symlink{Path: "lib/" + name, Target: "libc-actual.so"})
				}
			}
		}
		for index := range 6 {
			one, err := r.RuntimeClosure(r.Files[index].Path)
			if err != nil || !one.StaticDependenciesResolved {
				t.Fatal("fixture did not admit each individual entry", budget, err)
			}
		}
		got := r.NFSRuntimeClosure()
		if got.StaticDependenciesResolved || got.Reason != "runtime-budget" || len(got.Objects) != 0 || got.TotalBytes != 0 || got.RuntimeQualified || got.ExecutionAuthorized {
			t.Fatal("combined userspace budget was bypassed", budget, got)
		}
	}
}
