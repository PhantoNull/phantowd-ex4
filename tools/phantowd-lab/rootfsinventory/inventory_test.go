// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func minimalHeader(class elf.Class, order binary.ByteOrder, flags uint32) []byte {
	raw := make([]byte, 64)
	copy(raw, []byte{0x7f, 'E', 'L', 'F', byte(class), byte(elf.ELFDATA2LSB), 1})
	if order == binary.BigEndian {
		raw[5] = byte(elf.ELFDATA2MSB)
	}
	order.PutUint16(raw[16:], uint16(elf.ET_EXEC))
	order.PutUint16(raw[18:], uint16(elf.EM_ARM))
	order.PutUint32(raw[20:], 1)
	if class == elf.ELFCLASS32 {
		order.PutUint32(raw[36:], flags)
		order.PutUint16(raw[40:], 52)
	} else {
		order.PutUint32(raw[48:], flags)
		order.PutUint16(raw[52:], 64)
	}
	return raw
}

func TestInspectELFObservesExactHeaderFlagsInBothClassesAndByteOrders(t *testing.T) {
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		for _, order := range []binary.ByteOrder{binary.LittleEndian, binary.BigEndian} {
			for _, flags := range []uint32{0, 0x05000200, 0x05000400, 0xfedcba98} {
				info, err := inspectELF(bytes.NewReader(minimalHeader(class, order, flags)))
				if err != nil || info == nil || info.HeaderFlags == nil || *info.HeaderFlags != flags {
					t.Fatal("header flags not faithfully observed:", class, order, flags, info, err)
				}
				if flags == 0 {
					encoded, err := json.Marshal(info)
					if err != nil || !bytes.Contains(encoded, []byte(`"header_flags":0`)) {
						t.Fatal("observed zero flags were omitted:", string(encoded), err)
					}
				}
			}
		}
	}
}

type shortHeaderFlags struct{ io.ReaderAt }

func (r shortHeaderFlags) ReadAt(p []byte, offset int64) (int, error) {
	if len(p) == 4 && (offset == 36 || offset == 48) {
		return 2, nil
	}
	return r.ReaderAt.ReadAt(p, offset)
}

func TestInspectELFRefusesIncompleteFlagsWithoutPartialMetadata(t *testing.T) {
	for _, class := range []elf.Class{elf.ELFCLASS32, elf.ELFCLASS64} {
		reader := shortHeaderFlags{bytes.NewReader(minimalHeader(class, binary.LittleEndian, 0x05000200))}
		info, err := inspectELF(reader)
		if err == nil || info != nil {
			t.Fatal("short processor flags yielded partial ELF metadata:", info, err)
		}
	}
}

func TestExtractedARMHeaderPrerequisitesReachClosureWithoutExecution(t *testing.T) {
	for _, flags := range []uint32{0x05000200, 0x05000000, 0, 0x04000200, 0x05000400, 0x05800200} {
		root := t.TempDir()
		if err := os.WriteFile(filepath.Join(root, "service"), minimalHeader(elf.ELFCLASS32, binary.LittleEndian, flags), 0o600); err != nil {
			t.Fatal(err)
		}
		inventory, err := Inspect(root)
		if err != nil || len(inventory.Files) != 1 {
			t.Fatal("synthetic extracted ELF was not observed:", inventory, err)
		}
		candidate, err := inventory.RuntimeClosure("service")
		expected := flags == 0x05000200 || flags == 0x05000000
		if err != nil || candidate.StaticDependenciesResolved != expected || candidate.RuntimeQualified || candidate.ExecutionAuthorized ||
			(!expected && (candidate.Reason != "unsupported-arm-header" || len(candidate.Objects) != 0 || candidate.TotalBytes != 0)) {
			t.Fatal("actual header bytes were not bound to the closure prerequisite:", flags, candidate, err)
		}
	}
}

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
