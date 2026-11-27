// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"encoding/hex"
	"io"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

const SambaManifestLimit = 256 * 1024
const sambaCodeFormat = "phantowd-samba-code-v1"
const sambaCatalogPath = "usr/lib/gconv/gconv-modules"

var sambaCodeEntries = [...]string{
	"lib/ld-linux.so.3", "usr/sbin/smbd", "usr/bin/smbpasswd", "usr/bin/testparm",
	"usr/bin/pdbedit", "usr/bin/smbstatus", "usr/bin/smbcontrol",
	"usr/lib/samba/vfs/streams_xattr.so", "usr/lib/gconv/IBM850.so",
}

type sambaFileRow struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
	Mode   uint32 `json:"mode"`
}

type sambaAliasRow struct {
	Path   string `json:"path"`
	Target string `json:"target"`
}

// DecodeSambaCodeManifest reads the versioned description shipped in the
// trusted image. Inspection separately proves the exact code-only filesystem.
func DecodeSambaCodeManifest(input io.Reader) (*Plan, error) {
	var data struct {
		Format  string          `json:"format"`
		Files   []sambaFileRow  `json:"files"`
		Aliases []sambaAliasRow `json:"aliases"`
	}
	fields := map[string]bool{"format": true, "files": true, "aliases": true,
		"path": true, "sha256": true, "size": true, "mode": true, "target": true}
	if input == nil || configjson.Decode(input, &data, SambaManifestLimit, 4, fields) != nil ||
		data.Format != sambaCodeFormat || len(data.Files) > maxFiles ||
		data.Aliases == nil || len(data.Files)+len(data.Aliases) > maxBindings {
		return nil, ErrInvalid
	}
	required := map[string]uint32{sambaCatalogPath: 0444}
	for _, entry := range sambaCodeEntries {
		required[entry] = 0555
	}
	files := make([]File, 0, len(data.Files))
	for _, row := range data.Files {
		file := File{Path: row.Path, Size: row.Size, Mode: row.Mode}
		wantMode, requiredFile := required[row.Path]
		if !sambaCodePath(row.Path) || row.Mode != 0555 && row.Path != sambaCatalogPath ||
			requiredFile && row.Mode != wantMode || len(row.SHA256) != 64 || strings.ToLower(row.SHA256) != row.SHA256 {
			return nil, ErrInvalid
		}
		if _, err := hex.Decode(file.SHA256[:], []byte(row.SHA256)); err != nil {
			return nil, ErrInvalid
		}
		files = append(files, file)
		delete(required, row.Path)
	}
	if len(required) != 0 {
		return nil, ErrInvalid
	}
	aliases := make([]Alias, 0, len(data.Aliases))
	for _, row := range data.Aliases {
		if !sambaLibraryPath(row.Path) || !sambaLibraryPath(row.Target) ||
			row.Path == sambaCatalogPath || row.Target == sambaCatalogPath {
			return nil, ErrInvalid
		}
		aliases = append(aliases, Alias(row))
	}
	return NewPlan(files, aliases)
}

func sambaLibraryPath(name string) bool {
	return strings.HasPrefix(name, "lib/") || strings.HasPrefix(name, "usr/lib/")
}

func sambaCodePath(name string) bool {
	if sambaLibraryPath(name) {
		return true
	}
	for _, entry := range sambaCodeEntries {
		if name == entry {
			return true
		}
	}
	return false
}
