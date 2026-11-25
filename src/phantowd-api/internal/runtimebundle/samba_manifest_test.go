// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestDecodeSambaCodeManifestRequiresFixedCodeAndAliasRoles(t *testing.T) {
	digest := strings.Repeat("a", 64)
	files := make([]sambaFileRow, 0, len(sambaCodeEntries)+1)
	for _, entry := range sambaCodeEntries {
		files = append(files, sambaFileRow{Path: entry, SHA256: digest, Size: 17, Mode: 0555})
	}
	files = append(files, sambaFileRow{Path: sambaCatalogPath, SHA256: digest, Size: 19, Mode: 0444})
	encode := func(files []sambaFileRow, target string) []byte {
		t.Helper()
		data, err := json.Marshal(map[string]any{"format": sambaCodeFormat, "files": files,
			"aliases": []sambaAliasRow{{Path: "usr/lib/loader-alias.so", Target: target}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	valid := encode(files, "lib/ld-linux.so.3")
	plan, err := DecodeSambaCodeManifest(bytes.NewReader(valid))
	if err != nil || len(plan.files) != len(files) || len(plan.aliases) != 1 {
		t.Fatalf("fixed runtime manifest refused: %v", err)
	}
	withoutCatalog := encode(files[:len(files)-1], "lib/ld-linux.so.3")
	outsideAlias := encode(files, "usr/sbin/smbd")
	duplicateEntry := encode(append(append([]sambaFileRow(nil), files...), files[0]), "lib/ld-linux.so.3")
	writable := bytes.Replace(valid, []byte(`"mode":365`), []byte(`"mode":511`), 1)
	for _, invalid := range [][]byte{withoutCatalog, outsideAlias, duplicateEntry, writable} {
		if result, err := DecodeSambaCodeManifest(bytes.NewReader(invalid)); result != nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid runtime manifest accepted: %v", err)
		}
	}
}
