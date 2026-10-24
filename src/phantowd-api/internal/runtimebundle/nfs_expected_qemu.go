//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"encoding/hex"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

type nfsExpectedObjectQEMU struct {
	Path     string   `json:"path"`
	SHA256   string   `json:"sha256"`
	Size     int64    `json:"size"`
	Bindings []string `json:"bindings"`
}

type nfsExpectedReportQEMU struct {
	Format                     string                  `json:"format"`
	SchemaVersion              int                     `json:"schema_version"`
	RootDigest                 string                  `json:"root_digest_sha256"`
	ExpectedEntries            []string                `json:"expected_entries"`
	StaticDependenciesResolved *bool                   `json:"static_dependencies_resolved"`
	RuntimeQualified           *bool                   `json:"runtime_qualified"`
	ExecutionAuthorized        *bool                   `json:"execution_authorized"`
	FailedEntry                string                  `json:"failed_entry"`
	Reason                     string                  `json:"reason"`
	TotalBytes                 int64                   `json:"total_bytes"`
	Objects                    []nfsExpectedObjectQEMU `json:"objects"`
	Limitations                []string                `json:"limitations"`
}

// DecodeNFSExpectedQEMU consumes unsigned build metadata for disposable fixtures,
// not a product manifest, trusted-hash source, retained reference or execution grant.
// expectedRoot must come from the caller's separate build observation. No I/O.
func DecodeNFSExpectedQEMU(data []byte, expectedRoot [32]byte) (*Plan, error) {
	keys := map[string]bool{}
	for _, name := range []string{"format", "schema_version", "root_digest_sha256", "expected_entries",
		"static_dependencies_resolved", "runtime_qualified", "execution_authorized", "failed_entry", "reason",
		"total_bytes", "objects", "limitations", "path", "sha256", "size", "bindings"} {
		keys[name] = true
	}
	var report nfsExpectedReportQEMU
	if configjson.Decode(bytes.NewReader(data), &report, 128<<10, 8, keys) != nil {
		return nil, ErrInvalid
	}
	if expectedRoot == ([32]byte{}) || report.RootDigest != hex.EncodeToString(expectedRoot[:]) {
		return nil, ErrInvalid
	}
	entries := []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs", "usr/sbin/rpc.nfsd", "usr/sbin/rpc.statd", "usr/sbin/sm-notify"}
	if report.Format != "phantowd-nfs-runtime-candidate" || report.SchemaVersion != 1 ||
		!slices.Equal(report.ExpectedEntries, entries) || report.StaticDependenciesResolved == nil || !*report.StaticDependenciesResolved ||
		report.RuntimeQualified == nil || *report.RuntimeQualified || report.ExecutionAuthorized == nil || *report.ExecutionAuthorized ||
		report.FailedEntry != "" || report.Reason != "" || len(report.Limitations) == 0 ||
		len(report.Objects) == 0 || len(report.Objects) > maxFiles || report.TotalBytes <= 0 || report.TotalBytes > maxBytes {
		return nil, ErrInvalid
	}
	var files []File
	var aliases []Alias
	bindings := map[string]bool{}
	var total int64
	for _, object := range report.Objects {
		decoded, err := hex.DecodeString(object.SHA256)
		if err != nil || len(decoded) != 32 || hex.EncodeToString(decoded) != object.SHA256 ||
			object.Size <= 0 || object.Size > maxBytes-total {
			return nil, ErrInvalid
		}
		total += object.Size
		var digest [32]byte
		copy(digest[:], decoded)
		files = append(files, File{Path: object.Path, SHA256: digest, Size: object.Size, Mode: 0555})
		canonicalBinding := false
		for _, binding := range object.Bindings {
			if bindings[binding] || len(bindings) >= maxBindings {
				return nil, ErrInvalid
			}
			bindings[binding] = true
			if binding != object.Path {
				aliases = append(aliases, Alias{Path: binding, Target: object.Path})
			} else {
				canonicalBinding = true
			}
		}
		if !canonicalBinding {
			return nil, ErrInvalid
		}
	}
	if total != report.TotalBytes {
		return nil, ErrInvalid
	}
	for _, entry := range entries {
		if !bindings[entry] {
			return nil, ErrInvalid
		}
	}
	return NewPlan(files, aliases)
}
