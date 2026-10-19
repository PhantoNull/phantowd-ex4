// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package rootfsinventory

import (
	"slices"
	"strings"
)

// NFSRuntimeClosure covers the three userspace entries of the current NFSv3
// fixture, not kernel NFSD or a complete product runtime. Expectations and all
// objects come from ONE inventory; independent candidates cannot be mixed.
type NFSRuntimeClosure struct {
	Format                     string          `json:"format"`
	SchemaVersion              int             `json:"schema_version"`
	RootDigest                 string          `json:"root_digest_sha256"`
	ExpectedEntries            []string        `json:"expected_entries"`
	StaticDependenciesResolved bool            `json:"static_dependencies_resolved"`
	RuntimeQualified           bool            `json:"runtime_qualified"`
	ExecutionAuthorized        bool            `json:"execution_authorized"`
	FailedEntry                string          `json:"failed_entry,omitempty"`
	Reason                     string          `json:"reason,omitempty"`
	TotalBytes                 int64           `json:"total_bytes"`
	Objects                    []RuntimeObject `json:"objects,omitempty"`
	Limitations                []string        `json:"limitations"`
}

func (r Report) NFSRuntimeClosure() NFSRuntimeClosure {
	out := NFSRuntimeClosure{Format: "phantowd-nfs-runtime-candidate", SchemaVersion: 1,
		RootDigest:      r.RootDigest,
		ExpectedEntries: []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"},
		Limitations: []string{
			"offline three-entry ARM32 NFSv3 fixture code graph, not an approved runtime manifest",
			"no loader cache, environment, hwcaps, RPATH, token or symbol/load-order emulation",
			"dlopen, NSS, configuration, writable state and device access require separate evidence",
			"kernel NFSD, NLM/NSM/statd, protocol operation and product runtime coverage are not qualified",
			"ownership, capabilities, immutable retained references, signatures and execution are not qualified",
			"no mounting, copying, process launch, privileges or installation authority",
		}}
	fail := func(entry, reason string) NFSRuntimeClosure {
		out.FailedEntry, out.Reason = entry, reason
		return out // No objects/bytes/resolved result is published until ALL entries pass.
	}
	files := make(map[string]File, len(r.Files))
	for _, file := range r.Files {
		files[file.Path] = file
	}
	objects := make(map[string]*RuntimeObject)
	bindings := make(map[string]string)
	var total int64
	for _, entry := range out.ExpectedEntries {
		candidate, err := r.RuntimeClosure(entry)
		if err != nil {
			return fail(entry, "entry-refused")
		}
		if !candidate.StaticDependenciesResolved {
			return fail(entry, candidate.Reason)
		}
		entryObserved := false
		for _, object := range candidate.Objects {
			if slices.Contains(object.Bindings, entry) {
				elf := files[object.Path].ELF
				if elf == nil || elf.Interpreter != "/lib/ld-linux.so.3" {
					return fail(entry, "unsupported-entry-profile")
				}
				entryObserved = true
			}
			held := objects[object.Path]
			if held == nil {
				if len(objects) >= maxRuntimeObjects || object.Size > maxRuntimeBytes-total {
					return fail(entry, "runtime-budget")
				}
				total += object.Size
				held = &RuntimeObject{Path: object.Path, SHA256: object.SHA256, Size: object.Size}
				objects[object.Path] = held
			}
			// Canonical names count too: a consumer must materialize the whole
			// root, including objects requested only through library aliases.
			for _, name := range append(slices.Clone(object.Bindings), object.Path) {
				if prior, exists := bindings[name]; exists {
					if prior != object.Path {
						return fail(entry, "conflicting-binding")
					}
					continue
				}
				if len(bindings) >= maxRuntimeBindings {
					return fail(entry, "runtime-budget")
				}
				bindings[name] = object.Path
				held.Bindings = append(held.Bindings, name)
			}
		}
		if !entryObserved {
			return fail(entry, "unobserved-entry")
		}
	}
	for _, object := range objects {
		slices.Sort(object.Bindings)
		out.Objects = append(out.Objects, *object)
	}
	slices.SortFunc(out.Objects, func(a, b RuntimeObject) int { return strings.Compare(a.Path, b.Path) })
	out.TotalBytes, out.StaticDependenciesResolved = total, true
	return out
}
