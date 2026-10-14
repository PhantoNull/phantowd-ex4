// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// BuildSpec supplies declarations for an UNSIGNED schema1 manifest. Versions,
// source commit, target and hardware revisions are caller declarations, not
// build provenance or qualified device identities.
type BuildSpec struct {
	ReleaseVersion, Channel, ModelID string
	HardwareRevisions                []string
	SourceCommit                     string
	BuildrootVersion, KernelVersion  string
	MinimumInstaller                 string
}

// PayloadSpec selects an explicit flat filename and existing manifest role.
// Size and digest are always measured, never taken from caller declarations.
type PayloadSpec struct{ Name, Role string }

// BuildUnsignedManifest reads only the named regular files and emits complete
// deterministic schema1 JSON, sorted by revision/name, or no bytes on error.
// It signs nothing and creates no VerifiedManifest, file, trust or install grant.
// Payload observations are point-in-time; a future signer/installer must own
// immutable staging and independently reverify bytes and build provenance.
func BuildUnsignedManifest(spec BuildSpec, payloads []PayloadSpec, directory string, publicKey ed25519.PublicKey) ([]byte, error) {
	if len(publicKey) != ed25519.PublicKeySize || len(payloads) == 0 || len(payloads) > maxArtifacts ||
		len(spec.HardwareRevisions) == 0 || len(spec.HardwareRevisions) > maxHardwareRevisions {
		return nil, errors.New("invalid unsigned release inputs")
	}
	// Bound declarations before JSON allocation, version parsing or payload I/O.
	declarations := []string{spec.ReleaseVersion, spec.Channel, spec.ModelID, spec.SourceCommit,
		spec.BuildrootVersion, spec.KernelVersion, spec.MinimumInstaller}
	declarations = append(declarations, spec.HardwareRevisions...)
	for _, payload := range payloads {
		declarations = append(declarations, payload.Name, payload.Role)
	}
	remaining := maxManifestSize
	for _, value := range declarations {
		if len(value) > remaining {
			return nil, errors.New("unsigned release declarations exceed manifest bound")
		}
		remaining -= len(value)
	}
	manifest := Manifest{
		Format: manifestFormat, SchemaVersion: manifestVersion, Product: "phantowd",
		ReleaseVersion: spec.ReleaseVersion, Channel: spec.Channel, ModelID: spec.ModelID,
		HardwareRevisions: slices.Clone(spec.HardwareRevisions), SourceCommit: spec.SourceCommit,
		BuildrootVersion: spec.BuildrootVersion, KernelVersion: spec.KernelVersion,
		MinimumInstaller: spec.MinimumInstaller, SigningKeyID: "sha256:" + digest(publicKey),
		Artifacts: make([]Artifact, len(payloads)),
	}
	for i, payload := range payloads {
		// Internal placeholders permit reuse of ALL existing semantic gates
		// before any payload access. They never leave this function.
		manifest.Artifacts[i] = Artifact{Name: payload.Name, Role: payload.Role, SizeBytes: 1, SHA256: strings.Repeat("0", 64)}
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	slices.Sort(manifest.HardwareRevisions)
	slices.SortFunc(manifest.Artifacts, func(a, b Artifact) int { return strings.Compare(a.Name, b.Name) })
	if _, err := encodeUnsignedManifest(manifest); err != nil {
		return nil, err
	}
	rootBefore, err := os.Lstat(directory)
	if err != nil || !rootBefore.IsDir() || rootBefore.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("release payload directory is not a real directory")
	}
	// Size admission for the entire set precedes hashing any member. Sparse or
	// continuously growing files cannot turn a failed budget into unbounded reads.
	witnesses := make([]os.FileInfo, len(manifest.Artifacts))
	var total int64
	for i := range manifest.Artifacts {
		artifact := &manifest.Artifacts[i]
		before, err := os.Lstat(filepath.Join(directory, artifact.Name))
		if err != nil || !before.Mode().IsRegular() || before.Size() <= 0 || before.Size() > maxArtifactSize ||
			total > maxBundleSize-before.Size() {
			return nil, errors.New("release payload is unavailable, nonregular or over budget")
		}
		witnesses[i], artifact.SizeBytes = before, before.Size()
		total += before.Size()
	}
	// Measured sizes may add digits. Check the complete encoded size before
	// hashing payloads; the final digests have the same length as placeholders.
	if _, err := encodeUnsignedManifest(manifest); err != nil {
		return nil, err
	}
	for i := range manifest.Artifacts {
		artifact := &manifest.Artifacts[i]
		count, hash, err := hashRegularArtifact(directory, artifact.Name, artifact.SizeBytes)
		if err != nil || count != artifact.SizeBytes || hash == "" {
			return nil, errors.New("release payload read could not be confirmed")
		}
		artifact.SHA256 = hash
	}
	// Refuse observed set/root replacement or metadata drift, without claiming
	// to exclude privileged in-place writes or provide immutable staging.
	for i, artifact := range manifest.Artifacts {
		after, err := os.Lstat(filepath.Join(directory, artifact.Name))
		if err != nil || !os.SameFile(witnesses[i], after) || after.Mode() != witnesses[i].Mode() ||
			after.Size() != witnesses[i].Size() || !after.ModTime().Equal(witnesses[i].ModTime()) {
			return nil, errors.New("release payload set changed during preparation")
		}
	}
	rootAfter, err := os.Lstat(directory)
	if err != nil || !os.SameFile(rootBefore, rootAfter) || rootAfter.Mode() != rootBefore.Mode() ||
		!rootAfter.ModTime().Equal(rootBefore.ModTime()) {
		return nil, errors.New("release payload directory changed during preparation")
	}
	return encodeUnsignedManifest(manifest)
}

func encodeUnsignedManifest(manifest Manifest) ([]byte, error) {
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	data, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil || len(data)+1 > maxManifestSize {
		return nil, errors.New("unsigned release manifest exceeds encoding bound")
	}
	data = append(data, '\n')
	if err := checkManifestStructure(data); err != nil {
		return nil, err
	}
	return data, nil
}
