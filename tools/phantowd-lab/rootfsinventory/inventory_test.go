// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestInspectSyntheticRootIsDeterministic(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "bin"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "bin", "health"), []byte("#!/bin/sh\nexit 0\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "release"), []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	first, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if first.RootDigest == "" || first.RootDigest != second.RootDigest {
		t.Fatalf("root digest is not deterministic: %q != %q", first.RootDigest, second.RootDigest)
	}
	if first.Summary.RegularFiles != 2 || first.Summary.ScriptFiles != 1 || first.Summary.Directories != 1 {
		t.Fatalf("unexpected summary: %+v", first.Summary)
	}
	if first.Files[0].Path != "bin/health" || first.Files[0].ScriptInterpreter != "/bin/sh" {
		t.Fatalf("unexpected first file: %+v", first.Files[0])
	}
	overview := first.Compact()
	if overview.RootDigest != first.RootDigest || len(overview.ScriptInterpreters) != 1 || overview.ScriptInterpreters[0].Name != "/bin/sh" {
		t.Fatalf("unexpected compact overview: %+v", overview)
	}
}

func TestInspectRejectsFileRoot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-root")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Inspect(path); err == nil {
		t.Fatal("regular-file root was accepted")
	}
}

func TestInspectDoesNotFollowSymlink(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(root, "external")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.Symlinks != 1 || report.Summary.RegularFiles != 0 {
		t.Fatalf("symlink target was traversed: %+v", report.Summary)
	}
}

func TestInspectCurrentLinuxELF(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the current Windows test executable is PE, not ELF")
	}
	sourcePath, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	root := t.TempDir()
	target, err := os.OpenFile(filepath.Join(root, "test-binary"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o700)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(target, source); err != nil {
		t.Fatal(err)
	}
	if err := target.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.Summary.ELFFiles != 1 || report.Summary.ELFParseErrors != 0 || report.Files[0].ELF == nil {
		t.Fatalf("current Linux ELF was not inventoried: %+v", report)
	}
}
