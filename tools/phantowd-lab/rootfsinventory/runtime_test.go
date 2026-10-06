// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func runtimeELF(path string, needed ...string) File {
	flags := uint32(0x05000200)
	return File{Path: path, Size: 100, SHA256: strings.Repeat("a", 64), Kind: "elf",
		ELF: &ELFInfo{Class: "ELFCLASS32", ByteOrder: "ELFDATA2LSB", Machine: "EM_ARM", Type: "ET_DYN", HeaderFlags: &flags, Needed: needed}}
}

func TestRuntimeClosureRequiresObservedSupportedARMHeadersForEveryObject(t *testing.T) {
	for _, flags := range []uint32{0, 0x04000200, 0x06000200, 0x05000400, 0x05000600, 0x05800200} {
		for index := 0; index < 4; index++ {
			t.Run(fmt.Sprintf("flags-%08x-object-%d", flags, index), func(t *testing.T) {
				r := runtimeReport()
				r.Files[index].ELF.HeaderFlags = &flags
				result, err := r.RuntimeClosure("usr/sbin/service")
				if err != nil || result.StaticDependenciesResolved || result.Reason != "unsupported-arm-header" ||
					len(result.Objects) != 0 || result.TotalBytes != 0 || result.RuntimeQualified || result.ExecutionAuthorized {
					t.Fatal("incompatible header or partial candidate escaped:", result, err)
				}
			})
		}
	}
	for index := 0; index < 4; index++ {
		r := runtimeReport()
		r.Files[index].ELF.HeaderFlags = nil
		result, err := r.RuntimeClosure("usr/sbin/service")
		if err != nil || result.StaticDependenciesResolved || result.Reason != "unobserved-arm-header" || len(result.Objects) != 0 {
			t.Fatal("missing header was inferred as supported:", index, result, err)
		}
	}
	// AAELF32 allows the base procedure-call standard to be implied when
	// neither floating-point flag is set. Do not mislabel it as hard-float.
	r := runtimeReport()
	for _, item := range r.Files {
		*item.ELF.HeaderFlags = 0x05000000
	}
	result, err := r.RuntimeClosure("usr/sbin/service")
	if err != nil || !result.StaticDependenciesResolved || result.RuntimeQualified || result.ExecutionAuthorized {
		t.Fatal("implied base ABI was refused or became authority:", result, err)
	}
}

func runtimeReport() Report {
	main := runtimeELF("usr/sbin/service", "libprivate.so", "libc.so.6")
	main.ELF.Interpreter = "/lib/ld-linux.so.3"
	main.ELF.RunPath = []string{"/usr/lib/samba"}
	private := runtimeELF("usr/lib/samba/libprivate.so", "libc.so.6")
	return Report{Format: "phantowd-extracted-rootfs-inventory", SchemaVersion: 1, RootDigest: strings.Repeat("b", 64),
		Files:    []File{main, private, runtimeELF("lib/libc-actual.so"), runtimeELF("lib/ld-linux.so.3")},
		Symlinks: []Symlink{{Path: "lib/libc.so.6", Target: "libc-actual.so"}}}
}

func TestRuntimeClosureResolvesLiteralRunpathAndAliasesDeterministically(t *testing.T) {
	report := runtimeReport()
	first, err := report.RuntimeClosure("usr/sbin/service")
	if err != nil || !first.StaticDependenciesResolved || first.RuntimeQualified || first.ExecutionAuthorized || len(first.Objects) != 4 {
		t.Fatal(first, err)
	}
	if !reflect.DeepEqual(first.Objects[0].Bindings, []string{"lib/ld-linux.so.3"}) ||
		!reflect.DeepEqual(first.Objects[1].Bindings, []string{"lib/libc.so.6"}) {
		t.Fatal("requested loader aliases were lost:", first.Objects)
	}
	report.Files[0], report.Files[3] = report.Files[3], report.Files[0]
	second, err := report.RuntimeClosure("usr/sbin/service")
	if err != nil || !reflect.DeepEqual(first, second) {
		t.Fatal("inventory order changed the closure:", err)
	}
}

func TestRuntimeClosureNeverInheritsParentsRunpath(t *testing.T) {
	report := runtimeReport()
	report.Files[1].ELF.Needed = []string{"libchild.so"}
	report.Files = append(report.Files, runtimeELF("usr/lib/samba/libchild.so"))
	result, err := report.RuntimeClosure("usr/sbin/service")
	if err != nil || result.StaticDependenciesResolved || result.Reason != "unresolved-dependency" || len(result.Objects) != 0 {
		t.Fatal("parent RUNPATH was inherited or a partial manifest escaped:", result, err)
	}
}

func TestRuntimeClosureIgnoresEntirelyEmptyRunpath(t *testing.T) {
	r := runtimeReport()
	r.Files[1].ELF.RunPath = []string{""}
	result, err := r.RuntimeClosure("usr/sbin/service")
	if err != nil || !result.StaticDependenciesResolved || len(result.Objects) != 4 {
		t.Fatal("glibc ignores an entirely empty RUNPATH, unlike empty list components:", result, err)
	}
}

func TestRuntimeClosureRefusesUnsupportedOrConflictingEvidence(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*Report)
	}{
		{"rpath", func(r *Report) { r.Files[0].ELF.RPath = []string{"/lib"} }},
		{"origin", func(r *Report) { r.Files[0].ELF.RunPath = []string{"$ORIGIN/../lib"} }},
		{"relative-path", func(r *Report) { r.Files[0].ELF.RunPath = []string{"relative"} }},
		{"empty-component", func(r *Report) { r.Files[0].ELF.RunPath = []string{"/lib:"} }},
		{"wrong-abi", func(r *Report) { r.Files[1].ELF.Machine = "EM_PPC" }},
		{"parse-error", func(r *Report) { r.Files[1].ELFError = "bad" }},
		{"dependency-path", func(r *Report) { r.Files[0].ELF.Needed = []string{"../outside"} }},
		{"modifier", func(r *Report) { r.Files[0].ELF.LoaderModifiers = []string{"audit"} }},
		{"link-loop", func(r *Report) { r.Symlinks[0].Target = "libc.so.6" }},
		{"link-escape", func(r *Report) { r.Symlinks[0].Target = "../../outside" }},
		{"duplicate", func(r *Report) { r.Files = append(r.Files, r.Files[0]) }},
		{"shadow", func(r *Report) { r.Files = append(r.Files, runtimeELF("usr/lib/libc.so.6")) }},
		{"object-budget", func(r *Report) { r.Files[0].Size = maxRuntimeBytes + 1 }},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := runtimeReport()
			test.edit(&r)
			result, err := r.RuntimeClosure("usr/sbin/service")
			if err != nil || result.StaticDependenciesResolved || result.RuntimeQualified || result.ExecutionAuthorized || len(result.Objects) != 0 || result.Reason == "" {
				t.Fatal("unsafe partial runtime plan was accepted:", result, err)
			}
		})
	}
}

func TestRuntimeClosureChecksCyclesAndDirectoryLinks(t *testing.T) {
	r := runtimeReport()
	r.Files[1].ELF.RunPath = []string{"/usr/lib/samba"}
	r.Files[1].ELF.Needed = []string{"libprivate.so", "libc.so.6"}
	for i := range r.Files {
		if strings.HasPrefix(r.Files[i].Path, "lib/") {
			r.Files[i].Path = "usr/" + r.Files[i].Path
		}
	}
	r.Symlinks[0].Path = "usr/lib/libc.so.6"
	r.Symlinks = append(r.Symlinks, Symlink{Path: "lib", Target: "usr/lib"})
	result, err := r.RuntimeClosure("usr/sbin/service")
	if err != nil || !result.StaticDependenciesResolved || len(result.Objects) != 4 {
		t.Fatal("bounded cycles or inside-image directory links failed:", result, err)
	}
}

func TestRuntimeClosureBoundsCompleteObjectRoster(t *testing.T) {
	r := runtimeReport()
	for i := 0; i < maxRuntimeObjects; i++ {
		name := fmt.Sprintf("libchain%d.so", i)
		r.Files[0].ELF.Needed = append(r.Files[0].ELF.Needed, name)
		r.Files = append(r.Files, runtimeELF("lib/"+name))
	}
	result, err := r.RuntimeClosure("usr/sbin/service")
	if err != nil || result.StaticDependenciesResolved || result.Reason != "runtime-budget" || len(result.Objects) != 0 {
		t.Fatal(result, err)
	}
}

func FuzzRuntimeClosureNeverAuthorizesOrLeaksPartialPlan(f *testing.F) {
	f.Add("libc.so.6", "libc-actual.so", "/usr/lib/samba")
	f.Add("../outside", "../../outside", "$ORIGIN")
	f.Fuzz(func(t *testing.T, name, link, runpath string) {
		if len(name)+len(link)+len(runpath) > 8192 {
			t.Skip()
		}
		r := runtimeReport()
		r.Files[0].ELF.Needed = []string{name}
		r.Files[0].ELF.RunPath = []string{runpath}
		r.Symlinks[0].Target = link
		result, err := r.RuntimeClosure("usr/sbin/service")
		if err != nil {
			t.Fatal(err)
		}
		if result.ExecutionAuthorized || result.RuntimeQualified || (!result.StaticDependenciesResolved && (len(result.Objects) != 0 || result.TotalBytes != 0)) {
			t.Fatal("candidate became authority or leaked partial objects:", result)
		}
	})
}

func FuzzRuntimeClosureARMHeaderPrerequisites(f *testing.F) {
	f.Add(uint32(0x05000200), uint8(0), true)
	f.Add(uint32(0x05000000), uint8(3), true)
	f.Add(uint32(0x05000400), uint8(1), true)
	f.Add(uint32(0), uint8(2), false)
	f.Fuzz(func(t *testing.T, flags uint32, index uint8, present bool) {
		r := runtimeReport()
		r.Files[int(index)%len(r.Files)].ELF.HeaderFlags = &flags
		if !present {
			r.Files[int(index)%len(r.Files)].ELF.HeaderFlags = nil
		}
		result, err := r.RuntimeClosure("usr/sbin/service")
		expected := present && flags&0xff000000 == 0x05000000 && flags&(0x400|0x800000) == 0
		if err != nil || result.StaticDependenciesResolved != expected || result.RuntimeQualified || result.ExecutionAuthorized ||
			(!expected && (len(result.Objects) != 0 || result.TotalBytes != 0 || result.Reason == "")) {
			t.Fatal("header prerequisites became authority or leaked a partial candidate:", result, err)
		}
	})
}
