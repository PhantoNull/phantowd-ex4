// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func unsignedBuildFixture(t *testing.T) (BuildSpec, []PayloadSpec, string, ed25519.PrivateKey) {
	t.Helper()
	// Test-only key remains in memory; no private key material is stored.
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	for _, name := range []string{"z-rootfs.test", "a-kernel.test"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("synthetic-"+name), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return BuildSpec{ReleaseVersion: "v0.1.0-alpha.1", Channel: "nightly", ModelID: "wd-my-cloud-ex4",
			HardwareRevisions: []string{"board-r2", "board-r1"}, SourceCommit: strings.Repeat("1", 40),
			BuildrootVersion: "2025.02.18", KernelVersion: "6.18.55", MinimumInstaller: "v0.1.0"},
		[]PayloadSpec{{Name: "z-rootfs.test", Role: "test-rootfs"}, {Name: "a-kernel.test", Role: "test-kernel"}}, dir, key
}

func TestBuildUnsignedManifestDeterministicRoundTripAndNoAuthority(t *testing.T) {
	spec, payloads, dir, key := unsignedBuildFixture(t)
	public := key.Public().(ed25519.PublicKey)
	data, err := BuildUnsignedManifest(spec, payloads, dir, public)
	if err != nil {
		t.Fatal(err)
	}
	var manifest Manifest
	if err := decodeManifest(data, &manifest); err != nil || validateManifest(manifest) != nil {
		t.Fatal("builder output is not existing strict schema1", err)
	}
	if manifest.Artifacts[0].Name != "a-kernel.test" || manifest.HardwareRevisions[0] != "board-r1" {
		t.Fatal("non-deterministic ordering")
	}
	for _, artifact := range manifest.Artifacts {
		want := []byte("synthetic-" + artifact.Name)
		sum := sha256.Sum256(want)
		if artifact.SizeBytes != int64(len(want)) || artifact.SHA256 != hex.EncodeToString(sum[:]) {
			t.Fatal("payload size/digest was not measured")
		}
	}
	slices.Reverse(spec.HardwareRevisions)
	slices.Reverse(payloads)
	reordered, err := BuildUnsignedManifest(spec, payloads, dir, public)
	if err != nil || !bytes.Equal(data, reordered) {
		t.Fatal("ordering changes signed-byte candidate", err)
	}
	if spec.HardwareRevisions[0] != "board-r1" || payloads[0].Name != "a-kernel.test" {
		t.Fatal("builder modified caller slices")
	}
	verified, report, err := InspectManifest(bytes.NewReader(data), bytes.NewReader(make([]byte, ed25519.SignatureSize)), public,
		spec.ModelID, "board-r1", spec.Channel)
	if err != nil || verified != nil || report.SignatureValid || report.InstallationAuthorized {
		t.Fatal("unsigned candidate became verified authority", err)
	}
	// Fixture-only signature verifies the exact returned bytes with the existing
	// verifier; even this full successful check never authorizes installation.
	report, err = Inspect(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(key, data)), public, dir,
		spec.ModelID, "board-r1", spec.Channel)
	if err != nil || !report.Valid || report.InstallationAuthorized || report.HardwareQualified {
		t.Fatal("existing verifier roundtrip differs", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a-kernel.test"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	report, err = Inspect(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(key, data)), public, dir,
		spec.ModelID, "board-r1", spec.Channel)
	if err != nil || report.Valid || report.ArtifactsValid {
		t.Fatal("changed candidate payload was accepted", err)
	}
}

func TestBuildUnsignedManifestInvalidDeclarationsBeforePayloadIO(t *testing.T) {
	changes := []struct {
		name string
		edit func(*BuildSpec, *[]PayloadSpec)
	}{
		{"version", func(s *BuildSpec, _ *[]PayloadSpec) { s.ReleaseVersion = "1.0" }},
		{"channel", func(s *BuildSpec, _ *[]PayloadSpec) { s.Channel = "private" }},
		{"model", func(s *BuildSpec, _ *[]PayloadSpec) { s.ModelID = "../model" }},
		{"wildcard-revision", func(s *BuildSpec, _ *[]PayloadSpec) { s.HardwareRevisions = []string{"all"} }},
		{"duplicate-revision", func(s *BuildSpec, _ *[]PayloadSpec) { s.HardwareRevisions = []string{"r1", "r1"} }},
		{"no-revision", func(s *BuildSpec, _ *[]PayloadSpec) { s.HardwareRevisions = nil }},
		{"many-revisions", func(s *BuildSpec, _ *[]PayloadSpec) { s.HardwareRevisions = make([]string, 17) }},
		{"commit", func(s *BuildSpec, _ *[]PayloadSpec) { s.SourceCommit = "not-a-commit" }},
		{"buildroot", func(s *BuildSpec, _ *[]PayloadSpec) { s.BuildrootVersion = "latest" }},
		{"kernel", func(s *BuildSpec, _ *[]PayloadSpec) { s.KernelVersion = "6.18" }},
		{"installer", func(s *BuildSpec, _ *[]PayloadSpec) { s.MinimumInstaller = "unknown" }},
		{"bounded-declarations", func(s *BuildSpec, _ *[]PayloadSpec) { s.ReleaseVersion = strings.Repeat("1", maxManifestSize+1) }},
		{"bounded-encoded-declarations", func(s *BuildSpec, _ *[]PayloadSpec) {
			s.KernelVersion = "6.18." + strings.Repeat("1", maxManifestSize-512)
		}},
		{"traversal", func(_ *BuildSpec, p *[]PayloadSpec) { (*p)[0].Name = "../private-marker" }},
		{"duplicate-name", func(_ *BuildSpec, p *[]PayloadSpec) { (*p)[1].Name = (*p)[0].Name }},
		{"role", func(_ *BuildSpec, p *[]PayloadSpec) { (*p)[0].Role = "InvalidRole" }},
		{"no-payload", func(_ *BuildSpec, p *[]PayloadSpec) { *p = nil }},
		{"many-payloads", func(_ *BuildSpec, p *[]PayloadSpec) { *p = make([]PayloadSpec, 17) }},
	}
	for _, test := range changes {
		t.Run(test.name, func(t *testing.T) {
			spec, payloads, _, key := unsignedBuildFixture(t)
			test.edit(&spec, &payloads)
			data, err := BuildUnsignedManifest(spec, payloads, "missing-private-marker", key.Public().(ed25519.PublicKey))
			if err == nil || data != nil || strings.Contains(err.Error(), "directory") || strings.Contains(err.Error(), "private-marker") {
				t.Fatal("invalid declarations reached payload I/O, leaked input or returned output", err)
			}
		})
	}
	spec, payloads, _, _ := unsignedBuildFixture(t)
	for _, size := range []int{0, 31, 33} {
		if data, err := BuildUnsignedManifest(spec, payloads, "missing", make([]byte, size)); err == nil || data != nil {
			t.Fatal("invalid key length accepted")
		}
	}
}

func TestBuildUnsignedManifestRefusesPartialPayloadSets(t *testing.T) {
	for _, kind := range []string{"missing", "empty", "directory", "symlink"} {
		t.Run(kind, func(t *testing.T) {
			spec, payloads, dir, key := unsignedBuildFixture(t)
			name := filepath.Join(dir, "z-rootfs.test")
			if err := os.Remove(name); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "empty":
				if err := os.WriteFile(name, nil, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(name, 0700); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink(filepath.Join(dir, "a-kernel.test"), name); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			if data, err := BuildUnsignedManifest(spec, payloads, dir, key.Public().(ed25519.PublicKey)); err == nil || data != nil {
				t.Fatal("partial or nonregular set was published")
			}
		})
	}
}
