// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func nfsRuntimeReport() Report {
	r := runtimeReport()
	r.Files = r.Files[2:]
	for _, name := range []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"} {
		program := runtimeELF(name, "libc.so.6")
		program.ELF.Interpreter = "/lib/ld-linux.so.3"
		r.Files = append(r.Files, program)
	}
	return r
}

func TestNFSRuntimeClosureDoesNotPublishAnyPartialProgramSet(t *testing.T) {
	for _, entry := range []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"} {
		for _, failure := range []string{"missing", "header", "interpreter", "dependency"} {
			t.Run(entry+"/"+failure, func(t *testing.T) {
				r := nfsRuntimeReport()
				for index := range r.Files {
					if r.Files[index].Path != entry {
						continue
					}
					switch failure {
					case "missing":
						r.Files = append(r.Files[:index], r.Files[index+1:]...)
					case "header":
						r.Files[index].ELF.HeaderFlags = nil
					case "interpreter":
						r.Files[index].ELF.Interpreter = ""
					case "dependency":
						r.Files[index].ELF.Needed = []string{"missing.so"}
					}
					break
				}
				got := r.NFSRuntimeClosure()
				if got.StaticDependenciesResolved || got.RuntimeQualified || got.ExecutionAuthorized || got.FailedEntry != entry || got.Reason == "" || len(got.Objects) != 0 || got.TotalBytes != 0 {
					t.Fatal("partial runtime escaped", got)
				}
			})
		}
	}
}

func TestNFSRuntimeClosureAppliesWholeSetByteBudget(t *testing.T) {
	r := nfsRuntimeReport()
	for index := range r.Files {
		if strings.HasPrefix(r.Files[index].Path, "usr/sbin/") {
			r.Files[index].Size = maxRuntimeBytes / 2
		}
	}
	// Every individual program graph fits, while the union does not.
	for _, entry := range []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"} {
		one, err := r.RuntimeClosure(entry)
		if err != nil || !one.StaticDependenciesResolved {
			t.Fatal("invalid budget control", one, err)
		}
	}
	got := r.NFSRuntimeClosure()
	if got.StaticDependenciesResolved || got.Reason != "runtime-budget" || len(got.Objects) != 0 || got.TotalBytes != 0 {
		t.Fatal("combined budget was weakened by per-entry admission", got)
	}
}

func TestNFSRuntimeClosureCopiesCanonicalBindingsAndExpectations(t *testing.T) {
	r := nfsRuntimeReport()
	first := r.NFSRuntimeClosure()
	for _, object := range first.Objects {
		found := false
		for _, binding := range object.Bindings {
			found = found || binding == object.Path
		}
		if !found {
			t.Fatal("canonical materialization was omitted", object)
		}
	}
	first.ExpectedEntries[0] = "changed"
	first.Objects[0].Bindings[0] = "changed"
	if next := r.NFSRuntimeClosure(); next.ExpectedEntries[0] != "usr/sbin/rpcbind" || next.Objects[0].Bindings[0] == "changed" {
		t.Fatal("caller mutation changed later expected code inputs")
	}
}

func TestNFSRuntimeClosureBoundsCombinedObjectsAndBindings(t *testing.T) {
	for _, kind := range []string{"objects", "bindings"} {
		t.Run(kind, func(t *testing.T) {
			r := nfsRuntimeReport()
			for index := 2; index < 5; index++ {
				count := 90
				if kind == "bindings" {
					count = 400
				}
				for number := 0; number < count; number++ {
					name := fmt.Sprintf("nfs-%d-%03d.so", index, number)
					r.Files[index].ELF.Needed = append(r.Files[index].ELF.Needed, name)
					if kind == "objects" {
						r.Files = append(r.Files, runtimeELF("lib/"+name))
					} else {
						r.Symlinks = append(r.Symlinks, Symlink{Path: "lib/" + name, Target: "libc-actual.so"})
					}
				}
			}
			for _, name := range []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"} {
				one, err := r.RuntimeClosure(name)
				if err != nil || !one.StaticDependenciesResolved {
					t.Fatal("individual budget control failed", one.Reason, err)
				}
			}
			got := r.NFSRuntimeClosure()
			if got.StaticDependenciesResolved || got.Reason != "runtime-budget" || len(got.Objects) != 0 || got.TotalBytes != 0 {
				t.Fatal("combined budget produced partial code expectations", got)
			}
		})
	}
}

func TestNFSRuntimeClosureUnifiesFixedProgramsAndSharedLibraries(t *testing.T) {
	r := nfsRuntimeReport()
	got := r.NFSRuntimeClosure()
	if !got.StaticDependenciesResolved || got.RuntimeQualified || got.ExecutionAuthorized ||
		got.Format != "phantowd-nfs-runtime-candidate" || got.SchemaVersion != 1 ||
		got.RootDigest != r.RootDigest || len(got.Objects) != 5 || got.TotalBytes != 500 ||
		!reflect.DeepEqual(got.ExpectedEntries, []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"}) {
		t.Fatal("complete fixed runtime was not resolved once", got)
	}
	for left, right := 0, len(r.Files)-1; left < right; left, right = left+1, right-1 {
		r.Files[left], r.Files[right] = r.Files[right], r.Files[left]
	}
	if next := r.NFSRuntimeClosure(); !reflect.DeepEqual(got, next) {
		t.Fatal("inventory order changed canonical NFS runtime", next)
	}
}
