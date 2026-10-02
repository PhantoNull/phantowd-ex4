// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func exampleFile(name string) File {
	return File{Path: name, SHA256: sha256.Sum256([]byte("fixed")), Size: 5, Mode: 0555}
}

func TestPlanCopiesCanonicalCodeOnlyInputs(t *testing.T) {
	files := []File{exampleFile("usr/bin/service"), exampleFile("lib/libfixed.so")}
	aliases := []Alias{{"lib/libfixed.so.1", "lib/libfixed.so"}}
	p, err := NewPlan(files, aliases)
	if err != nil {
		t.Fatal(err)
	}
	files[0].SHA256 = [32]byte{}
	aliases[0].Target = "host/escape"
	if p.files[0].Path != "lib/libfixed.so" || p.files[1].SHA256 == ([32]byte{}) || p.aliases[0].Target != "lib/libfixed.so" ||
		p.bytes != 10 || p.nodes["usr"] != 'd' || p.nodes["usr/bin"] != 'd' || len(p.nodes) != 7 {
		t.Fatal("input copy, canonical ordering or complete node census lost")
	}
}

func TestPlanRefusesPathAndBudgetAmbiguity(t *testing.T) {
	paths := []string{"", ".", "../outside", "a/../b", "/usr/bin/service", "usr//bin/service", "a/", "a\\b", "a\x00b", "a b", "é", strings.Repeat("a", 256), strings.Repeat("a/", 16) + "b"}
	for _, name := range paths {
		if _, err := NewPlan([]File{exampleFile(name)}, nil); err == nil {
			t.Fatalf("unsafe path accepted: %q", name)
		}
	}
	for _, mutate := range []func(*File){
		func(f *File) { f.SHA256 = [32]byte{} }, func(f *File) { f.Size = 0 },
		func(f *File) { f.Size = maxBytes + 1 }, func(f *File) { f.Mode = 0755 },
		func(f *File) { f.Mode = 04755 },
	} {
		f := exampleFile("lib/object")
		mutate(&f)
		if _, err := NewPlan([]File{f}, nil); err == nil {
			t.Fatal("invalid file metadata accepted")
		}
	}
	for _, files := range [][]File{
		{exampleFile("a"), exampleFile("a")}, {exampleFile("a"), exampleFile("a/b")},
		{exampleFile("a/b"), exampleFile("a")},
	} {
		if _, err := NewPlan(files, nil); err == nil {
			t.Fatal("conflicting file hierarchy accepted")
		}
	}
	if _, err := NewPlan(nil, nil); err == nil {
		t.Fatal("empty manifest accepted")
	}
	files := make([]File, maxFiles+1)
	if _, err := NewPlan(files, nil); err == nil {
		t.Fatal("oversized file roster accepted")
	}
}

func TestPlanRefusesAliasChainsAndHierarchyConflicts(t *testing.T) {
	for _, aliases := range [][]Alias{
		{{"lib/alias", "missing"}}, {{"lib/file", "lib/file"}},
		{{"lib/alias", "lib/file"}, {"lib/alias", "lib/file"}},
		{{"lib/alias", "lib/file"}, {"lib/chain", "lib/alias"}},
		{{"lib", "lib/file"}}, {{"lib/file/alias", "lib/file"}},
		{{"x/y", "lib/file"}, {"x", "lib/file"}},
	} {
		if _, err := NewPlan([]File{exampleFile("lib/file")}, aliases); err == nil {
			t.Fatal("invalid alias topology accepted", aliases)
		}
	}
}

func TestPlanAndObservationCannotCrossSerializationBoundary(t *testing.T) {
	p, err := NewPlan([]File{exampleFile("lib/file")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := json.Marshal(p); err == nil {
		t.Fatal("plan serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &Plan{}); err == nil {
		t.Fatal("plan deserialized")
	}
	if _, err := json.Marshal(Observation{}); err == nil {
		t.Fatal("observation serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &Observation{}); err == nil {
		t.Fatal("observation deserialized")
	}
}

func TestPlanBoundsAggregateBytesAndBindingCount(t *testing.T) {
	a, b := exampleFile("a"), exampleFile("b")
	a.Size, b.Size = maxBytes/2, maxBytes/2+1
	if _, err := NewPlan([]File{a, b}, nil); err == nil {
		t.Fatal("aggregate byte budget bypassed")
	}
	aliases := make([]Alias, maxBindings)
	for i := range aliases {
		aliases[i] = Alias{Path: fmt.Sprintf("aliases/file-%d", i), Target: "a"}
	}
	if _, err := NewPlan([]File{exampleFile("a")}, aliases); err == nil {
		t.Fatal("aggregate binding budget bypassed")
	}
}

func FuzzPlanPathHierarchy(f *testing.F) {
	f.Add("lib/file", "lib/alias", "lib/file")
	f.Add("../outside", "a", "b")
	f.Add("a/b", "a", "a/b")
	f.Fuzz(func(t *testing.T, name, alias, target string) {
		p, err := NewPlan([]File{exampleFile(name)}, []Alias{{Path: alias, Target: target}})
		if err != nil {
			return
		}
		if !canonical(name) || !canonical(alias) || name == alias || target != name ||
			p.nodes[name] != 'f' || p.nodes[alias] != 'l' || p.bytes != 5 || len(p.nodes) > maxNodes {
			t.Fatal("invalid path topology survived construction")
		}
	})
}
