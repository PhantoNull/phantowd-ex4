//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestFixtureManifestDecodeIsBoundedAndExact(t *testing.T) {
	good := `{"Format":"phantowd-qemu-pending-client-inputs-v1"}`
	if _, err := decodeManifest([]byte(good + "\n")); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"", "null", "{}", good + " {}", good + " true", good + " junk",
		strings.Replace(good, "v1", "v2", 1), strings.Replace(good, "}", `,"Other":true}`, 1),
		good + strings.Repeat(" ", 128<<10),
		`{"Format":"phantowd-qemu-pending-client-inputs-v1","RootFiles":[{"Other":true}]}`} {
		if _, err := decodeManifest([]byte(bad)); err == nil {
			t.Fatal("invalid fixture metadata accepted")
		}
	}
}

func TestFixturePlanUsesIndependentExpectedBytesAndExactModes(t *testing.T) {
	files := []fixtureFile{{Path: "fixture/pending-write", SHA256: strings.Repeat("11", 32), Size: 1, Mode: 0555}}
	if _, err := plan(files, nil); err != nil {
		t.Fatal(err)
	}
	for _, digest := range []string{"", "11", strings.Repeat("11", 33), strings.Repeat("zz", 32)} {
		candidate := append([]fixtureFile(nil), files...)
		candidate[0].SHA256 = digest
		if _, err := plan(candidate, nil); err == nil {
			t.Fatal("invalid expected digest accepted")
		}
	}
	for _, mode := range []uint32{0, 0755, 0777} {
		candidate := append([]fixtureFile(nil), files...)
		candidate[0].Mode = mode
		if _, err := plan(candidate, nil); err == nil {
			t.Fatal("mutable/unknown code mode accepted")
		}
	}
	encoded, err := json.Marshal(fixtureManifest{Format: "phantowd-qemu-pending-client-inputs-v1", RootFiles: files})
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeManifest(encoded)
	if err != nil || len(decoded.RootFiles) != 1 || decoded.RootFiles[0] != files[0] {
		t.Fatal("expected metadata changed", err)
	}
}
