// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"encoding/hex"
	"errors"
	"path"
	"slices"
	"strings"
	"unicode/utf8"
)

const (
	maxRuntimeObjects        = 256
	maxRuntimeBindings       = 1024
	maxRuntimeEdges          = 4096
	maxRuntimeBytes    int64 = 64 * 1024 * 1024
)

// RuntimeObject is research evidence: aliases in the extracted image map to
// one inventoried regular ELF. Nothing here is a device execution grant.
type RuntimeObject struct {
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Size     int64    `json:"size"`
	Bindings []string `json:"bindings"`
}

type RuntimeClosure struct {
	Format                     string          `json:"format"`
	SchemaVersion              int             `json:"schema_version"`
	RootDigest                 string          `json:"root_digest_sha256"`
	Entry                      string          `json:"entry"`
	PathModel                  string          `json:"path_model"`
	StaticDependenciesResolved bool            `json:"static_dependencies_resolved"`
	RuntimeQualified           bool            `json:"runtime_qualified"`
	ExecutionAuthorized        bool            `json:"execution_authorized"`
	Reason                     string          `json:"reason,omitempty"`
	TotalBytes                 int64           `json:"total_bytes"`
	Objects                    []RuntimeObject `json:"objects,omitempty"`
	Limitations                []string        `json:"limitations"`
}

// RuntimeClosure resolves only inventoried text, never host symlink targets or
// executables. The bounded ARM32 little-endian model supports literal per-object
// RUNPATH then /lib,/usr/lib; it refuses RPATH, tokens, modifiers and shadowing.
// No ld.so.cache/env/hwcaps, loaded-object/symbol-order or dlopen emulation.
// Observed headers must declare EABI5/base procedure calls and no BE-8 code;
// this does not qualify instruction sets, build attributes or symbol versions.
func (r Report) RuntimeClosure(entry string) (RuntimeClosure, error) {
	out := RuntimeClosure{Format: "phantowd-elf-runtime-candidate", SchemaVersion: 1,
		RootDigest: r.RootDigest, Entry: entry, PathModel: "arm32-literal-runpath-lib-usr-lib",
		Limitations: []string{
			"offline extracted-view DT_NEEDED/interpreter graph, never an approved runtime manifest",
			"no loader cache, environment, hwcaps, RPATH, token or symbol/load-order emulation",
			"dlopen modules, NSS, data/configuration, writable state and device access require separate evidence",
			"ownership, capabilities, source immutability, ABI compatibility and signature trust are not qualified",
			"no mounting, copying, process launch, privilege or installation authority",
		}}
	if !runtimeRelative(entry) {
		return out, errors.New("entry must be a canonical image-relative path")
	}
	fail := func(reason string) (RuntimeClosure, error) { out.Reason = reason; return out, nil }
	if r.Format != "phantowd-extracted-rootfs-inventory" || r.SchemaVersion != 1 || !runtimeHash(r.RootDigest) {
		return fail("invalid-inventory")
	}
	if len(r.Files)+len(r.Symlinks)+len(r.SpecialEntries) > maxEntries {
		return fail("inventory-budget")
	}
	files := make(map[string]File, len(r.Files))
	links := make(map[string]string, len(r.Symlinks))
	special := make(map[string]bool, len(r.SpecialEntries))
	seen := make(map[string]bool)
	add := func(name string) bool {
		if !runtimeRelative(name) || seen[name] {
			return false
		}
		seen[name] = true
		return true
	}
	for _, file := range r.Files {
		if !add(file.Path) {
			return fail("conflicting-inventory")
		}
		files[file.Path] = file
	}
	for _, link := range r.Symlinks {
		if !add(link.Path) {
			return fail("conflicting-inventory")
		}
		links[link.Path] = link.Target
	}
	for _, item := range r.SpecialEntries {
		if !add(item.Path) {
			return fail("conflicting-inventory")
		}
		special[item.Path] = true
	}
	resolve := func(request string) (string, bool, bool) {
		candidate := request
		for count := 0; count <= 32; count++ {
			parts := strings.Split(candidate, "/")
			changed := false
			for i := range parts {
				prefix := strings.Join(parts[:i+1], "/")
				if target, exists := links[prefix]; exists {
					if target == "" || len(target) > 4096 || !runtimeText(target) {
						return "", false, true
					}
					var rewritten string
					if strings.HasPrefix(target, "/") {
						rewritten = strings.TrimPrefix(target, "/")
					} else {
						rewritten = path.Join(path.Dir(prefix), target)
					}
					if i+1 < len(parts) {
						rewritten = path.Join(rewritten, strings.Join(parts[i+1:], "/"))
					}
					if !runtimeRelative(rewritten) {
						return "", false, true
					}
					candidate, changed = rewritten, true
					break
				}
				if special[prefix] || (i+1 < len(parts) && files[prefix].Path != "") {
					return "", false, true
				}
			}
			if !changed {
				_, exists := files[candidate]
				return candidate, exists, false
			}
		}
		return "", false, true
	}
	objects := make(map[string]*RuntimeObject)
	queue := []string{}
	bindings, edges := 0, 0
	var total int64
	request := func(name string) string {
		canonical, exists, invalid := resolve(name)
		if invalid {
			return "invalid-link-or-entry"
		}
		if !exists {
			return "unresolved-dependency"
		}
		file := files[canonical]
		if file.Kind != "elf" || file.ELF == nil || file.ELFError != "" || !runtimeHash(file.SHA256) || file.Size <= 0 {
			return "invalid-elf-evidence"
		}
		if file.ELF.Class != "ELFCLASS32" || file.ELF.ByteOrder != "ELFDATA2LSB" || file.ELF.Machine != "EM_ARM" ||
			(file.ELF.Type != "ET_DYN" && file.ELF.Type != "ET_EXEC") {
			return "unsupported-abi"
		}
		if file.ELF.HeaderFlags == nil {
			return "unobserved-arm-header"
		}
		flags := *file.ELF.HeaderFlags
		// AAELF32 section 5.2: EABI version in bits 24..31; hardware
		// procedure-call ABI at bit 10 and BE-8 executable code at bit 23.
		// Neither explicit soft-float nor implied base ABI proves ARMv5
		// instruction compatibility; attributes remain a separate gate.
		if flags&0xff000000 != 0x05000000 || flags&0x00000400 != 0 || flags&0x00800000 != 0 {
			return "unsupported-arm-header"
		}
		object := objects[canonical]
		if object == nil {
			if len(objects) >= maxRuntimeObjects || file.Size > maxRuntimeBytes-total {
				return "runtime-budget"
			}
			total += file.Size
			object = &RuntimeObject{Path: canonical, SHA256: file.SHA256, Size: file.Size}
			objects[canonical] = object
			queue = append(queue, canonical)
		}
		if !slices.Contains(object.Bindings, name) {
			if bindings >= maxRuntimeBindings {
				return "runtime-budget"
			}
			bindings++
			object.Bindings = append(object.Bindings, name)
		}
		return ""
	}
	if reason := request(entry); reason != "" {
		return fail(reason)
	}
	globalNames := make(map[string]string)
	for position := 0; position < len(queue); position++ {
		info := files[queue[position]].ELF
		if len(info.RPath) > 0 || len(info.RunPath) > 1 || len(info.LoaderModifiers) > 0 {
			return fail("unsupported-load-search")
		}
		dirs := []string{}
		// glibc decompose_rpath ignores an entirely empty value. An empty
		// component of a nonempty list remains unsupported (cwd search).
		if len(info.RunPath) == 1 && info.RunPath[0] != "" {
			for _, dir := range strings.Split(info.RunPath[0], ":") {
				if !strings.HasPrefix(dir, "/") || !runtimeRelative(strings.TrimPrefix(dir, "/")) || strings.Contains(dir, "$") {
					return fail("unsupported-load-search")
				}
				dirs = append(dirs, strings.TrimPrefix(dir, "/"))
				if len(dirs) > 16 {
					return fail("runtime-budget")
				}
			}
		}
		dirs = append(dirs, "lib", "usr/lib")
		if info.Interpreter != "" {
			if !strings.HasPrefix(info.Interpreter, "/") || !runtimeRelative(strings.TrimPrefix(info.Interpreter, "/")) {
				return fail("unsupported-interpreter")
			}
			if reason := request(strings.TrimPrefix(info.Interpreter, "/")); reason != "" {
				return fail(reason)
			}
		}
		for _, name := range info.Needed {
			edges++
			if edges > maxRuntimeEdges {
				return fail("runtime-budget")
			}
			if len(name) > 255 || !runtimeRelative(name) || strings.ContainsAny(name, "/$") {
				return fail("unsupported-dependency-name")
			}
			selected, selectedCanonical := "", ""
			for _, dir := range dirs {
				candidate := dir + "/" + name
				canonical, exists, invalid := resolve(candidate)
				if invalid {
					return fail("invalid-link-or-entry")
				}
				if !exists {
					continue
				}
				if selected != "" && canonical != selectedCanonical {
					return fail("ambiguous-library")
				}
				if selected == "" {
					selected, selectedCanonical = candidate, canonical
				}
			}
			if selected == "" {
				return fail("unresolved-dependency")
			}
			if previous, exists := globalNames[name]; exists && previous != selectedCanonical {
				return fail("ambiguous-library")
			}
			globalNames[name] = selectedCanonical
			if reason := request(selected); reason != "" {
				return fail(reason)
			}
		}
	}
	for _, object := range objects {
		slices.Sort(object.Bindings)
		out.Objects = append(out.Objects, *object)
	}
	slices.SortFunc(out.Objects, func(a, b RuntimeObject) int { return strings.Compare(a.Path, b.Path) })
	out.TotalBytes, out.StaticDependenciesResolved = total, true
	return out, nil
}

func runtimeText(value string) bool {
	if !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r < 32 || r == 127 || r == '\\' {
			return false
		}
	}
	return true
}

func runtimeRelative(value string) bool {
	return value != "" && value != "." && len(value) <= 4096 && !strings.HasPrefix(value, "/") &&
		value != ".." && !strings.HasPrefix(value, "../") && path.Clean(value) == value && runtimeText(value)
}

func runtimeHash(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
