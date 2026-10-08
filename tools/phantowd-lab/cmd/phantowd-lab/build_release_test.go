// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/releaseverify"
)

func TestBuildReleaseManifestCommandProducesUnsignedSchema1(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "test-payload.bin"), []byte("synthetic payload"), 0600); err != nil {
		t.Fatal(err)
	}
	// Test-only private key remains in memory; only the public fixture is a file.
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(t.TempDir(), "public-key")
	if err := os.WriteFile(keyPath, public, 0600); err != nil {
		t.Fatal(err)
	}
	args := []string{"build-release-manifest", "--artifacts", root, "--public-key", keyPath,
		"--release-version", "v0.1.0-alpha.1", "--channel", "nightly", "--model", "wd-my-cloud-ex4",
		"--revision", "board-r2", "--revision", "board-r1", "--source-commit", strings.Repeat("1", 40),
		"--buildroot-version", "2025.02.18", "--kernel-version", "6.18.55", "--minimum-installer", "v0.1.0",
		"--artifact", "test-payload.bin:test-payload"}
	var output bytes.Buffer
	code, err := run(args, &output)
	if err != nil || code != 0 {
		t.Fatal("new release builder command unavailable", code, err)
	}
	var manifest releaseverify.Manifest
	if err := json.Unmarshal(output.Bytes(), &manifest); err != nil || len(manifest.Artifacts) != 1 {
		t.Fatal("invalid command output", err)
	}
	report, err := releaseverify.Inspect(bytes.NewReader(output.Bytes()), bytes.NewReader(ed25519.Sign(private, output.Bytes())),
		public, root, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || !report.Valid || report.InstallationAuthorized || report.HardwareQualified {
		t.Fatal("command/verifier mismatch", err)
	}
	before := append([]byte(nil), output.Bytes()...)
	output.Reset()
	code, err = run(args, &output)
	if err != nil || code != 0 || !bytes.Equal(before, output.Bytes()) {
		t.Fatal("nondeterministic command", code, err)
	}
	for _, extra := range [][]string{
		{"unexpected-positional"}, {"--private-key", "private-marker"}, {"--artifact", "../private-marker:test"},
		{"--artifact", "test-payload.bin:test-payload"}, {"--artifact", "ambiguous"},
		{"--revision", "all"}, {"--release-version", "invalid"},
	} {
		output.Reset()
		code, err := run(append(append([]string(nil), args...), extra...), &output)
		if err == nil || code != 1 || output.Len() != 0 {
			t.Fatal("invalid command emitted metadata", code, err)
		}
	}
}
