// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectVerifiedExactTargetBundle(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("synthetic EX4 update payload"))
	report, err := Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || !report.SignatureValid || !report.ArtifactsChecked || !report.ArtifactsValid || !report.TargetMatched || !report.ChannelMatched {
		t.Fatalf("valid bundle rejected: %+v", report)
	}
	if report.InstallationAuthorized || report.HardwareQualified {
		t.Fatalf("metadata verification incorrectly authorized install or hardware: %+v", report)
	}
	if !strings.Contains(strings.Join(report.Limitations, " "), "install-time re-verification") {
		t.Fatalf("missing installation-time verification boundary: %+v", report.Limitations)
	}
	if report.SigningKeyID == "" || len(report.Artifacts) != 1 || !report.Artifacts[0].Valid {
		t.Fatalf("verified metadata missing from report: %+v", report)
	}
}

func TestInspectRejectsInvalidSignatureAndTargetMismatch(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("signed bytes"))
	badSignature := append([]byte(nil), fixture.signature...)
	badSignature[0] ^= 0xff
	report, err := Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(badSignature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || report.SignatureValid || report.ArtifactsChecked {
		t.Fatalf("invalid signature accepted: report=%+v err=%v", report, err)
	}

	report, err = Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r2", "nightly")
	if err != nil || report.Valid || report.TargetMatched || report.ArtifactsChecked {
		t.Fatalf("non-target hardware accepted: report=%+v err=%v", report, err)
	}
	report, err = Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "stable")
	if err != nil || report.Valid || report.ChannelMatched || report.ArtifactsChecked {
		t.Fatalf("wrong channel accepted: report=%+v err=%v", report, err)
	}
	wildcard := makeBundle(t, "wd-my-cloud-ex4", []string{"all"}, []byte("payload"))
	report, err = Inspect(bytes.NewReader(wildcard.manifest), bytes.NewReader(wildcard.signature), wildcard.publicKey, wildcard.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || report.ArtifactsChecked {
		t.Fatalf("wildcard hardware revision accepted: report=%+v err=%v", report, err)
	}
}

func TestInspectDetectsChangedPayload(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("expected payload"))
	if err := os.WriteFile(filepath.Join(fixture.directory, "rootfs.swu"), []byte("tampered payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || report.ArtifactsValid || report.Artifacts[0].SHA256Match {
		t.Fatalf("changed payload was not rejected: report=%+v err=%v", report, err)
	}
}

func TestInspectRejectsTraversalAndDuplicateJSONKeys(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	manifest := strings.Replace(string(fixture.manifest), `"name":"rootfs.swu"`, `"name":"../rootfs.swu"`, 1)
	manifestBytes := []byte(manifest)
	signature := ed25519.Sign(fixture.privateKey, manifestBytes)
	report, err := Inspect(bytes.NewReader(manifestBytes), bytes.NewReader(signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || report.ArtifactsChecked || len(report.Artifacts) != 0 {
		t.Fatalf("path traversal filename was not rejected: report=%+v err=%v", report, err)
	}

	duplicate := []byte(`{"format":"phantowd-release-manifest","format":"other"}`)
	if _, err := Inspect(bytes.NewReader(duplicate), bytes.NewReader(make([]byte, ed25519.SignatureSize)), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly"); err == nil || !strings.Contains(err.Error(), "duplicate") {
		t.Fatalf("duplicate field was accepted: %v", err)
	}
}

func TestInspectRejectsNonSemVerReleaseMetadata(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	manifest := strings.Replace(string(fixture.manifest), `"release_version":"v0.1.0"`, `"release_version":"v00.1.0"`, 1)
	manifestBytes := []byte(manifest)
	report, err := Inspect(bytes.NewReader(manifestBytes), bytes.NewReader(ed25519.Sign(fixture.privateKey, manifestBytes)), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || report.ArtifactsChecked || report.ArtifactsValid {
		t.Fatalf("non-SemVer release version was accepted: report=%+v err=%v", report, err)
	}
	if !strings.Contains(strings.Join(report.Findings, " "), "strict v-prefixed SemVer") {
		t.Fatalf("missing strict version-policy finding: %+v", report.Findings)
	}
}

func TestInspectRejectsMissingFileAndWrongKeyID(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	if err := os.Remove(filepath.Join(fixture.directory, "rootfs.swu")); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || !report.ArtifactsChecked || report.ArtifactsValid {
		t.Fatalf("missing file accepted: report=%+v err=%v", report, err)
	}

	wrongKey := make([]byte, ed25519.PublicKeySize)
	copy(wrongKey, fixture.publicKey)
	wrongKey[0] ^= 1
	report, err = Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), wrongKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || report.SignatureValid || report.ArtifactsChecked {
		t.Fatalf("wrong trust key accepted: report=%+v err=%v", report, err)
	}
}

func TestInspectSkipsPayloadReadsForOversizedBundle(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	var manifest Manifest
	if err := json.Unmarshal(fixture.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.Artifacts = []Artifact{
		{Name: "a.swu", Role: "swupdate-bundle", SizeBytes: 800 * 1024 * 1024, SHA256: strings.Repeat("a", 64)},
		{Name: "b.swu", Role: "swupdate-bundle", SizeBytes: 800 * 1024 * 1024, SHA256: strings.Repeat("b", 64)},
		{Name: "c.swu", Role: "swupdate-bundle", SizeBytes: 800 * 1024 * 1024, SHA256: strings.Repeat("c", 64)},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(fixture.privateKey, data)), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || report.Valid || report.ArtifactsChecked || len(report.Artifacts) != 0 {
		t.Fatalf("oversized bundle was read or accepted: report=%+v err=%v", report, err)
	}
	if !strings.Contains(strings.Join(report.Findings, " "), "combined artifact size") {
		t.Fatalf("missing size-budget finding: %+v", report)
	}
}

func TestHashRegularArtifactRejectsSymlink(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(t.TempDir(), "payload")
	if err := os.WriteFile(target, []byte("payload"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "payload.swu")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	if _, _, err := hashRegularArtifact(directory, "payload.swu", int64(len("payload"))); err == nil {
		t.Fatal("symlink artifact was accepted")
	}
}

type bundleFixture struct {
	manifest   []byte
	signature  []byte
	publicKey  ed25519.PublicKey
	privateKey ed25519.PrivateKey
	directory  string
}

func makeBundle(t *testing.T, model string, revisions []string, payload []byte) bundleFixture {
	t.Helper()
	seed := sha256.Sum256([]byte("releaseverify deterministic synthetic test key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	payloadHash := sha256.Sum256(payload)
	manifest := Manifest{
		Format: manifestFormat, SchemaVersion: manifestVersion, Product: "phantowd",
		ReleaseVersion: "v0.1.0", Channel: "nightly", ModelID: model,
		HardwareRevisions: revisions, SourceCommit: strings.Repeat("a", 40),
		BuildrootVersion: "2025.02.18", KernelVersion: "6.18.53",
		MinimumInstaller: "v0.1.0", SigningKeyID: "sha256:" + hex.EncodeToString(keyHash[:]),
		Artifacts: []Artifact{{Name: "rootfs.swu", Role: "swupdate-bundle", SizeBytes: int64(len(payload)), SHA256: hex.EncodeToString(payloadHash[:])}},
	}
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "rootfs.swu"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	return bundleFixture{manifest: data, signature: ed25519.Sign(privateKey, data), publicKey: publicKey, privateKey: privateKey, directory: directory}
}
