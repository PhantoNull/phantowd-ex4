//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"encoding/hex"
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

// NFSExpectedPlanQEMU converts independently supplied, unsigned build evidence
// into code expectations only. It grants no provenance, retention or execution.
// A trusted containing constructor must separately bind the model/build,
// inspect/retain the original protected root and validate the actual ELF closure.
// No input bytes, root digest or asserted booleans become an authority token.
func NFSExpectedPlanQEMU(data []byte) (*Plan, error) {
	var document struct {
		Format        string   `json:"format"`
		SchemaVersion int      `json:"schema_version"`
		RootDigest    string   `json:"root_digest_sha256"`
		Entries       []string `json:"expected_entries"`
		Resolved      *bool    `json:"static_dependencies_resolved"`
		Qualified     *bool    `json:"runtime_qualified"`
		Authorized    *bool    `json:"execution_authorized"`
		FailedEntry   string   `json:"failed_entry,omitempty"`
		Reason        string   `json:"reason,omitempty"`
		TotalBytes    int64    `json:"total_bytes"`
		Objects       []struct {
			Path     string   `json:"path"`
			SHA256   string   `json:"sha256"`
			Size     int64    `json:"size"`
			Bindings []string `json:"bindings"`
		} `json:"objects"`
		Limitations []string `json:"limitations"`
	}
	keys := map[string]bool{}
	for _, key := range []string{"format", "schema_version", "root_digest_sha256", "expected_entries",
		"static_dependencies_resolved", "runtime_qualified", "execution_authorized", "failed_entry", "reason",
		"total_bytes", "objects", "path", "sha256", "size", "bindings", "limitations"} {
		keys[key] = true
	}
	if configjson.Decode(bytes.NewReader(data), &document, 128<<10, 8, keys) != nil ||
		document.Format != "phantowd-nfs-runtime-candidate" || document.SchemaVersion != 1 ||
		document.Resolved == nil || !*document.Resolved || document.Qualified == nil || *document.Qualified ||
		document.Authorized == nil || *document.Authorized || document.FailedEntry != "" || document.Reason != "" ||
		!slices.Equal(document.Entries, []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"}) ||
		len(document.Objects) < 4 || len(document.Objects) > maxFiles ||
		len(document.Limitations) == 0 || len(document.Limitations) > 16 {
		return nil, ErrInvalid
	}
	if _, ok := nfsExpectedHashQEMU(document.RootDigest); !ok {
		return nil, ErrInvalid
	}
	for _, limitation := range document.Limitations {
		if limitation == "" || len(limitation) > 512 {
			return nil, ErrInvalid
		}
	}
	files := make([]File, 0, len(document.Objects))
	aliases := []Alias{}
	bindings := map[string]string{}
	paths := map[string]bool{}
	var total int64
	for _, object := range document.Objects {
		hash, ok := nfsExpectedHashQEMU(object.SHA256)
		if !ok || !canonical(object.Path) || paths[object.Path] || object.Size <= 0 || object.Size > maxBytes-total ||
			len(object.Bindings) == 0 || !slices.Contains(object.Bindings, object.Path) {
			return nil, ErrInvalid
		}
		total += object.Size
		paths[object.Path] = true
		files = append(files, File{Path: object.Path, SHA256: hash, Size: object.Size, Mode: 0555})
		for _, binding := range object.Bindings {
			if !canonical(binding) || bindings[binding] != "" || len(bindings) >= maxBindings {
				return nil, ErrInvalid
			}
			bindings[binding] = object.Path
			if binding != object.Path {
				aliases = append(aliases, Alias{Path: binding, Target: object.Path})
			}
		}
	}
	if document.TotalBytes != total {
		return nil, ErrInvalid
	}
	for _, entry := range append(slices.Clone(document.Entries), "lib/ld-linux.so.3") {
		if bindings[entry] == "" {
			return nil, ErrInvalid
		}
	}
	return NewPlan(files, aliases)
}

func nfsExpectedHashQEMU(value string) ([32]byte, bool) {
	var result [32]byte
	if len(value) != 64 || strings.ToLower(value) != value {
		return result, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(result) {
		return result, false
	}
	copy(result[:], decoded)
	return result, result != ([32]byte{})
}
