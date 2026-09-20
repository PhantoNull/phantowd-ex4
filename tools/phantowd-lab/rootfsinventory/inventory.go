// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package rootfsinventory builds a deterministic, read-only manifest from an
// already extracted firmware root. It never follows symlinks or executes any
// inspected file.
package rootfsinventory

import (
	"bytes"
	"crypto/sha256"
	"debug/elf"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

const maxEntries = 250000

// Summary contains counts for the inspected extracted tree.
type Summary struct {
	Directories    int   `json:"directories"`
	RegularFiles   int   `json:"regular_files"`
	Symlinks       int   `json:"symlinks"`
	SpecialFiles   int   `json:"special_files"`
	TotalBytes     int64 `json:"total_bytes"`
	ELFFiles       int   `json:"elf_files"`
	ScriptFiles    int   `json:"script_files"`
	ELFParseErrors int   `json:"elf_parse_errors"`
}

// ELFInfo captures loader-facing facts without disassembling or executing the
// binary.
type ELFInfo struct {
	Class       string   `json:"class"`
	ByteOrder   string   `json:"byte_order"`
	Type        string   `json:"type"`
	Machine     string   `json:"machine"`
	OSABI       string   `json:"os_abi"`
	Interpreter string   `json:"interpreter,omitempty"`
	SONAME      string   `json:"soname,omitempty"`
	Needed      []string `json:"needed,omitempty"`
}

// File records one regular file. Hashes and paths belong in private analysis
// output when the input contains proprietary or identity-bearing material.
type File struct {
	Path              string   `json:"path"`
	Size              int64    `json:"size"`
	Mode              string   `json:"mode"`
	SHA256            string   `json:"sha256"`
	Kind              string   `json:"kind"`
	ScriptInterpreter string   `json:"script_interpreter,omitempty"`
	ELF               *ELFInfo `json:"elf,omitempty"`
	ELFError          string   `json:"elf_error,omitempty"`
}

// Symlink records link text but the scanner never resolves or opens the target.
type Symlink struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// Special records an entry that was deliberately not opened.
type Special struct {
	Path string `json:"path"`
	Mode string `json:"mode"`
}

// Report is a deterministic inventory of an extracted tree. It is an evidence
// manifest, not a package-manager-derived SBOM.
type Report struct {
	Format         string    `json:"format"`
	SchemaVersion  int       `json:"schema_version"`
	Scope          string    `json:"scope"`
	RootDigest     string    `json:"root_digest_sha256"`
	Summary        Summary   `json:"summary"`
	Files          []File    `json:"files"`
	Symlinks       []Symlink `json:"symlinks,omitempty"`
	SpecialEntries []Special `json:"special_entries,omitempty"`
	Limitations    []string  `json:"limitations"`
}

// NamedCount is a stable frequency entry used by the compact overview.
type NamedCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// Overview omits file paths and hashes while retaining the deterministic root
// digest and high-level runtime dependency evidence.
type Overview struct {
	Format             string       `json:"format"`
	SchemaVersion      int          `json:"schema_version"`
	Scope              string       `json:"scope"`
	RootDigest         string       `json:"root_digest_sha256"`
	Summary            Summary      `json:"summary"`
	ELFMachines        []NamedCount `json:"elf_machines,omitempty"`
	ELFClasses         []NamedCount `json:"elf_classes,omitempty"`
	ScriptInterpreters []NamedCount `json:"script_interpreters,omitempty"`
	RequiredLibraries  []NamedCount `json:"required_libraries,omitempty"`
	Limitations        []string     `json:"limitations"`
}

// Inspect walks root lexically, hashes regular files and parses ELF metadata.
// Symlinks and special files are never followed or opened.
func Inspect(root string) (Report, error) {
	report := Report{
		Format:        "phantowd-extracted-rootfs-inventory",
		SchemaVersion: 1,
		Scope:         "host-extracted-view",
		Limitations: []string{
			"this is a file and ELF-dependency manifest, not a complete package-manager SBOM",
			"host extraction may not preserve original SquashFS ownership, modes, device nodes, or xattrs",
			"version and license claims require corroboration from vendor manifests or upstream metadata",
		},
	}

	rootInfo, err := os.Lstat(root)
	if err != nil {
		return report, err
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		return report, errors.New("refusing symbolic-link root")
	}
	if !rootInfo.IsDir() {
		return report, errors.New("rootfs inventory input must be a directory")
	}
	root, err = filepath.Abs(root)
	if err != nil {
		return report, err
	}

	digest := sha256.New()
	entries := 0
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == root {
			return nil
		}
		entries++
		if entries > maxEntries {
			return fmt.Errorf("rootfs contains more than %d entries", maxEntries)
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}

		switch {
		case info.IsDir():
			report.Summary.Directories++
			writeDigestFields(digest, "directory", relative, info.Mode().String())
			return nil

		case info.Mode()&os.ModeSymlink != 0:
			target, err := os.Readlink(path)
			if err != nil {
				return err
			}
			report.Summary.Symlinks++
			report.Symlinks = append(report.Symlinks, Symlink{Path: relative, Target: target})
			writeDigestFields(digest, "symlink", relative, target)
			return nil

		case info.Mode().IsRegular():
			fileReport, err := inspectFile(path, relative, info)
			if err != nil {
				return err
			}
			report.Summary.RegularFiles++
			report.Summary.TotalBytes += fileReport.Size
			if fileReport.ELF != nil || fileReport.ELFError != "" {
				report.Summary.ELFFiles++
			}
			if fileReport.ELFError != "" {
				report.Summary.ELFParseErrors++
			}
			if fileReport.ScriptInterpreter != "" {
				report.Summary.ScriptFiles++
			}
			report.Files = append(report.Files, fileReport)
			writeDigestFields(digest, "file", relative, strconv.FormatInt(fileReport.Size, 10), fileReport.Mode, fileReport.SHA256)
			return nil

		default:
			report.Summary.SpecialFiles++
			report.SpecialEntries = append(report.SpecialEntries, Special{Path: relative, Mode: info.Mode().String()})
			writeDigestFields(digest, "special", relative, info.Mode().String())
			return nil
		}
	})
	if err != nil {
		return report, err
	}
	report.RootDigest = hex.EncodeToString(digest.Sum(nil))
	return report, nil
}

// Compact returns a path-free summary suitable for logs and canonical notes.
func (report Report) Compact() Overview {
	machines := make(map[string]int)
	classes := make(map[string]int)
	interpreters := make(map[string]int)
	libraries := make(map[string]int)
	for _, file := range report.Files {
		if file.ScriptInterpreter != "" {
			interpreters[file.ScriptInterpreter]++
		}
		if file.ELF == nil {
			continue
		}
		machines[file.ELF.Machine]++
		classes[file.ELF.Class]++
		for _, library := range file.ELF.Needed {
			libraries[library]++
		}
	}
	return Overview{
		Format:             report.Format,
		SchemaVersion:      report.SchemaVersion,
		Scope:              report.Scope,
		RootDigest:         report.RootDigest,
		Summary:            report.Summary,
		ELFMachines:        sortedCounts(machines),
		ELFClasses:         sortedCounts(classes),
		ScriptInterpreters: sortedCounts(interpreters),
		RequiredLibraries:  sortedCounts(libraries),
		Limitations:        append([]string(nil), report.Limitations...),
	}
}

func inspectFile(path, relative string, before fs.FileInfo) (File, error) {
	report := File{Path: relative, Size: before.Size(), Mode: before.Mode().String(), Kind: "file"}
	opened, err := os.Open(path)
	if err != nil {
		return report, err
	}
	defer opened.Close()
	openedInfo, err := opened.Stat()
	if err != nil {
		return report, err
	}
	if !openedInfo.Mode().IsRegular() {
		return report, fmt.Errorf("%s changed and is no longer a regular file", relative)
	}
	if !os.SameFile(before, openedInfo) {
		return report, fmt.Errorf("%s changed identity before inspection", relative)
	}
	if openedInfo.Size() != before.Size() {
		return report, fmt.Errorf("%s changed size before inspection", relative)
	}

	hasher := sha256.New()
	if _, err := io.Copy(hasher, opened); err != nil {
		return report, err
	}
	report.SHA256 = hex.EncodeToString(hasher.Sum(nil))
	after, err := opened.Stat()
	if err != nil {
		return report, err
	}
	if after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return report, fmt.Errorf("%s changed during inspection", relative)
	}

	var prefix [128]byte
	n, readErr := opened.ReadAt(prefix[:], 0)
	if readErr != nil && !errors.Is(readErr, io.EOF) {
		return report, readErr
	}
	data := prefix[:n]
	if bytes.HasPrefix(data, []byte{0x7f, 'E', 'L', 'F'}) {
		report.Kind = "elf"
		elfInfo, err := inspectELF(opened)
		if err != nil {
			report.Kind = "elf-unparsed"
			report.ELFError = err.Error()
		} else {
			report.ELF = elfInfo
		}
	} else if bytes.HasPrefix(data, []byte("#!")) {
		report.Kind = "script"
		report.ScriptInterpreter = scriptInterpreter(data)
	}
	return report, nil
}

func inspectELF(reader io.ReaderAt) (*ELFInfo, error) {
	parsed, err := elf.NewFile(reader)
	if err != nil {
		return nil, err
	}
	defer parsed.Close()
	info := &ELFInfo{
		Class:     parsed.Class.String(),
		ByteOrder: parsed.Data.String(),
		Type:      parsed.Type.String(),
		Machine:   parsed.Machine.String(),
		OSABI:     parsed.OSABI.String(),
	}
	if values, err := parsed.DynString(elf.DT_NEEDED); err == nil {
		info.Needed = append(info.Needed, values...)
		sort.Strings(info.Needed)
	}
	if values, err := parsed.DynString(elf.DT_SONAME); err == nil && len(values) > 0 {
		info.SONAME = values[0]
	}
	for _, program := range parsed.Progs {
		if program.Type != elf.PT_INTERP || program.Filesz == 0 || program.Filesz > 4096 {
			continue
		}
		value, err := io.ReadAll(io.LimitReader(program.Open(), int64(program.Filesz)))
		if err != nil {
			return nil, err
		}
		info.Interpreter = strings.TrimRight(string(value), "\x00")
		break
	}
	return info, nil
}

func scriptInterpreter(data []byte) string {
	line := data
	if index := bytes.IndexByte(line, '\n'); index >= 0 {
		line = line[:index]
	}
	fields := strings.Fields(strings.TrimSpace(strings.TrimPrefix(string(line), "#!")))
	if len(fields) == 0 {
		return "unknown"
	}
	return fields[0]
}

func writeDigestFields(target hash.Hash, fields ...string) {
	for _, field := range fields {
		_, _ = io.WriteString(target, strconv.Itoa(len(field)))
		_, _ = io.WriteString(target, ":")
		_, _ = io.WriteString(target, field)
	}
	_, _ = io.WriteString(target, "\n")
}

func sortedCounts(values map[string]int) []NamedCount {
	result := make([]NamedCount, 0, len(values))
	for name, count := range values {
		result = append(result, NamedCount{Name: name, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Count != result[j].Count {
			return result[i].Count > result[j].Count
		}
		return result[i].Name < result[j].Name
	})
	return result
}
