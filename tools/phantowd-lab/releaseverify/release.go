// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package releaseverify checks a signed PhantoWD release description and its
// regular-file payloads. It deliberately has no installation or device path.
package releaseverify

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

const (
	manifestFormat  = "phantowd-release-manifest"
	manifestVersion = 1
	maxManifestSize = 64 * 1024
	maxArtifacts    = 16
	maxArtifactSize = int64(1024 * 1024 * 1024)
	maxBundleSize   = int64(2 * 1024 * 1024 * 1024)
)

var (
	identifierPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{0,63}$`)
	filenamePattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._+-]{0,127}$`)
	rolePattern             = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)
	componentVersionPattern = regexp.MustCompile(`^v?[0-9]+\.[0-9]+\.[0-9]+$`)
	commitPattern           = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	digestPattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

// Manifest is the versioned, signed metadata accompanying release assets.
// The detached signature covers the exact bytes of the JSON file.
type Manifest struct {
	Format            string     `json:"format"`
	SchemaVersion     int        `json:"schema_version"`
	Product           string     `json:"product"`
	ReleaseVersion    string     `json:"release_version"`
	Channel           string     `json:"channel"`
	ModelID           string     `json:"model_id"`
	HardwareRevisions []string   `json:"hardware_revisions"`
	SourceCommit      string     `json:"source_commit"`
	BuildrootVersion  string     `json:"buildroot_version"`
	KernelVersion     string     `json:"kernel_version"`
	MinimumInstaller  string     `json:"minimum_installer"`
	SigningKeyID      string     `json:"signing_key_id"`
	Artifacts         []Artifact `json:"artifacts"`
}

// Artifact describes one file in the bundle directory.
type Artifact struct {
	Name      string `json:"name"`
	Role      string `json:"role"`
	SizeBytes int64  `json:"size_bytes"`
	SHA256    string `json:"sha256"`
}

// Report deliberately distinguishes cryptographic validity from model
// matching and from hardware qualification. Valid never authorizes install.
type Report struct {
	Format                 string           `json:"format"`
	SchemaVersion          int              `json:"schema_version"`
	Valid                  bool             `json:"valid"`
	SignatureValid         bool             `json:"signature_valid"`
	ArtifactsChecked       bool             `json:"artifacts_checked"`
	ArtifactsValid         bool             `json:"artifacts_valid"`
	TargetMatched          bool             `json:"target_matched"`
	ChannelMatched         bool             `json:"channel_matched"`
	InstallationAuthorized bool             `json:"installation_authorized"`
	HardwareQualified      bool             `json:"hardware_qualified"`
	ManifestSHA256         string           `json:"manifest_sha256,omitempty"`
	SigningKeyID           string           `json:"signing_key_id,omitempty"`
	ReleaseVersion         string           `json:"release_version,omitempty"`
	Channel                string           `json:"channel,omitempty"`
	ModelID                string           `json:"model_id,omitempty"`
	HardwareRevisions      []string         `json:"hardware_revisions,omitempty"`
	RequestedModelID       string           `json:"requested_model_id,omitempty"`
	RequestedHardware      string           `json:"requested_hardware_revision,omitempty"`
	RequestedChannel       string           `json:"requested_channel,omitempty"`
	Artifacts              []ArtifactResult `json:"artifacts"`
	UpdatePolicy           *UpdatePolicy    `json:"update_policy,omitempty"`
	Findings               []string         `json:"findings"`
	Limitations            []string         `json:"limitations"`
}

// UpdatePolicy reports only whether a fully verified release is newer than a
// caller-supplied installed version. It never authorizes installation.
type UpdatePolicy struct {
	Evaluated              bool   `json:"evaluated"`
	CurrentVersion         string `json:"current_version,omitempty"`
	ReleaseVersion         string `json:"release_version,omitempty"`
	StrictlyNewer          bool   `json:"strictly_newer"`
	InstallationAuthorized bool   `json:"installation_authorized"`
	Finding                string `json:"finding,omitempty"`
}

// ArtifactResult avoids echoing arbitrary local paths into the report.
type ArtifactResult struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	Expected    int64  `json:"expected_size_bytes"`
	Actual      int64  `json:"actual_size_bytes,omitempty"`
	SHA256Match bool   `json:"sha256_match"`
	Valid       bool   `json:"valid"`
}

// VerifiedManifest is created only after signature, schema, exact target, and
// channel checks pass. It exposes immutable copies of the signed artifact list
// so a transport can fetch exactly those files before hashing them locally.
type VerifiedManifest struct {
	manifest Manifest
	report   Report
}

// Artifacts returns a copy of the signed payload specifications.
func (v *VerifiedManifest) Artifacts() []Artifact {
	if v == nil {
		return nil
	}
	return append([]Artifact(nil), v.manifest.Artifacts...)
}

// ReleaseVersion returns the version covered by the verified signature.
func (v *VerifiedManifest) ReleaseVersion() string {
	if v == nil {
		return ""
	}
	return v.manifest.ReleaseVersion
}

// Channel returns the channel covered by the verified signature.
func (v *VerifiedManifest) Channel() string {
	if v == nil {
		return ""
	}
	return v.manifest.Channel
}

// InspectManifest verifies signed metadata and the exact requested target
// before a caller downloads any payload. publicKey must come from a separately
// trusted source. No key is embedded and no installation is authorized.
func InspectManifest(manifestReader, signatureReader io.Reader, publicKey ed25519.PublicKey, modelID, hardwareRevision, channel string) (*VerifiedManifest, Report, error) {
	report := Report{
		Format:        "phantowd-release-verification",
		SchemaVersion: 1,
		Artifacts:     []ArtifactResult{},
		Findings:      []string{},
		Limitations: []string{
			"the supplied public key is caller-selected; trust-anchor provisioning is not verified",
			"hardware qualification, anti-rollback policy, and installation are not evaluated",
			"artifact hashes describe bytes read during this check; later immutability and install-time re-verification are not evaluated",
			"this host-only verifier never accesses a device or writes an artifact",
		},
		RequestedModelID:       modelID,
		RequestedHardware:      hardwareRevision,
		RequestedChannel:       channel,
		InstallationAuthorized: false,
		HardwareQualified:      false,
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, report, errors.New("trusted public key must be exactly 32 bytes")
	}
	if !identifierPattern.MatchString(modelID) || !validHardwareRevision(hardwareRevision) {
		return nil, report, errors.New("requested model and hardware revision must be lowercase identifiers")
	}
	if channel != "stable" && channel != "beta" && channel != "nightly" {
		return nil, report, errors.New("requested channel must be stable, beta, or nightly")
	}

	manifestBytes, err := io.ReadAll(io.LimitReader(manifestReader, maxManifestSize+1))
	if err != nil {
		return nil, report, fmt.Errorf("read release manifest: %w", err)
	}
	if len(manifestBytes) == 0 || int64(len(manifestBytes)) > maxManifestSize {
		return nil, report, errors.New("release manifest is empty or exceeds 64 KiB")
	}
	report.ManifestSHA256 = digest(manifestBytes)

	signature, err := io.ReadAll(io.LimitReader(signatureReader, ed25519.SignatureSize+1))
	if err != nil {
		return nil, report, fmt.Errorf("read release signature: %w", err)
	}
	if len(signature) != ed25519.SignatureSize || !ed25519.Verify(publicKey, manifestBytes, signature) {
		report.Findings = append(report.Findings, "detached Ed25519 signature is invalid")
	} else {
		report.SignatureValid = true
	}

	var manifest Manifest
	if err := decodeStrict(manifestBytes, &manifest); err != nil {
		return nil, report, fmt.Errorf("invalid release manifest: %w", err)
	}
	report.ReleaseVersion = manifest.ReleaseVersion
	report.Channel = manifest.Channel
	report.ModelID = manifest.ModelID
	report.HardwareRevisions = append([]string(nil), manifest.HardwareRevisions...)

	keyFingerprint := "sha256:" + digest(publicKey)
	if manifest.SigningKeyID != keyFingerprint {
		report.Findings = append(report.Findings, "manifest signing_key_id does not match the supplied public key")
	} else {
		report.SigningKeyID = keyFingerprint
	}

	manifestValid := true
	if err := validateManifest(manifest); err != nil {
		manifestValid = false
		report.Findings = append(report.Findings, err.Error())
	}
	if manifest.ModelID == modelID && contains(manifest.HardwareRevisions, hardwareRevision) {
		report.TargetMatched = true
	} else {
		report.Findings = append(report.Findings, "release does not explicitly target the requested model and hardware revision")
	}
	if manifest.Channel == channel {
		report.ChannelMatched = true
	} else {
		report.Findings = append(report.Findings, "release channel does not match the requested channel")
	}
	if !report.SignatureValid || manifest.SigningKeyID != keyFingerprint || !manifestValid || !report.TargetMatched || !report.ChannelMatched {
		return nil, report, nil
	}
	return &VerifiedManifest{manifest: manifest, report: report}, report, nil
}

// VerifyArtifacts hashes each signed payload from a directory containing only
// regular files. Its report describes the bytes read in this invocation.
func (v *VerifiedManifest) VerifyArtifacts(artifactDirectory string) Report {
	if v == nil {
		return Report{Format: "phantowd-release-verification", Findings: []string{"manifest was not verified"}, Limitations: []string{"artifact checks require a verified signed manifest"}}
	}
	report := v.report
	report.ArtifactsChecked = true
	artifactOK := true
	for _, artifact := range v.manifest.Artifacts {
		result := ArtifactResult{Name: artifact.Name, Role: artifact.Role, Expected: artifact.SizeBytes}
		if !validArtifactName(artifact.Name) || artifact.SizeBytes < 0 || artifact.SizeBytes > maxArtifactSize || !digestPattern.MatchString(artifact.SHA256) {
			result.Valid = false
			artifactOK = false
			report.Artifacts = append(report.Artifacts, result)
			continue
		}
		actualSize, actualDigest, fileErr := hashRegularArtifact(artifactDirectory, artifact.Name, artifact.SizeBytes)
		result.Actual = actualSize
		result.SHA256Match = fileErr == nil && actualDigest == artifact.SHA256
		result.Valid = fileErr == nil && actualSize == artifact.SizeBytes && result.SHA256Match
		if !result.Valid {
			artifactOK = false
			if fileErr != nil {
				report.Findings = append(report.Findings, "artifact "+artifact.Name+" is unavailable or not a regular file")
			} else if actualSize != artifact.SizeBytes {
				report.Findings = append(report.Findings, "artifact "+artifact.Name+" size does not match the signed manifest")
			} else {
				report.Findings = append(report.Findings, "artifact "+artifact.Name+" SHA-256 does not match the signed manifest")
			}
		}
		report.Artifacts = append(report.Artifacts, result)
	}
	report.ArtifactsValid = artifactOK && len(v.manifest.Artifacts) > 0
	report.Valid = report.SignatureValid && report.ArtifactsValid && report.TargetMatched && report.ChannelMatched && len(report.Findings) == 0
	return report
}

// Inspect verifies the signature, schema, exact requested target, channel, and
// payload size/hash. It never authorizes installation.
func Inspect(manifestReader, signatureReader io.Reader, publicKey ed25519.PublicKey, artifactDirectory, modelID, hardwareRevision, channel string) (Report, error) {
	verified, report, err := InspectManifest(manifestReader, signatureReader, publicKey, modelID, hardwareRevision, channel)
	if err != nil || verified == nil {
		return report, err
	}
	return verified.VerifyArtifacts(artifactDirectory), nil
}

// AssessUpgradeVersion adds an optional anti-rollback comparison to a report.
// A true StrictlyNewer result is only a host-side version-policy observation;
// the caller-supplied key, hardware qualification, persistent rollback state,
// install-time re-verification, and installation remain outside this tool.
func AssessUpgradeVersion(report Report, currentVersion string) Report {
	policy := &UpdatePolicy{
		CurrentVersion:         currentVersion,
		ReleaseVersion:         report.ReleaseVersion,
		InstallationAuthorized: false,
	}
	if !report.Valid {
		policy.Finding = "full signature, target, channel, and artifact verification is required"
	} else if currentVersion == "" {
		policy.Finding = "current installed version is required"
	} else {
		policy.Evaluated = true
		if err := CheckMonotonicUpgrade(currentVersion, report.ReleaseVersion); err != nil {
			policy.Finding = err.Error()
		} else {
			policy.StrictlyNewer = true
		}
	}
	report.UpdatePolicy = policy
	return report
}

func validateManifest(manifest Manifest) error {
	var problems []string
	if manifest.Format != manifestFormat || manifest.SchemaVersion != manifestVersion {
		problems = append(problems, "unsupported release manifest format or schema version")
	}
	if manifest.Product != "phantowd" {
		problems = append(problems, "product must be phantowd")
	}
	if _, err := parseVersion(manifest.ReleaseVersion); err != nil {
		problems = append(problems, "release_version must use strict v-prefixed SemVer 2.0 syntax without build metadata")
	}
	if _, err := parseVersion(manifest.MinimumInstaller); err != nil {
		problems = append(problems, "minimum_installer must use strict v-prefixed SemVer 2.0 syntax without build metadata")
	}
	if manifest.Channel != "stable" && manifest.Channel != "beta" && manifest.Channel != "nightly" {
		problems = append(problems, "channel must be stable, beta, or nightly")
	}
	if !identifierPattern.MatchString(manifest.ModelID) {
		problems = append(problems, "model_id is invalid")
	}
	if !commitPattern.MatchString(manifest.SourceCommit) {
		problems = append(problems, "source_commit must be a lowercase 40- or 64-character hexadecimal commit")
	}
	if !componentVersionPattern.MatchString(manifest.BuildrootVersion) || !componentVersionPattern.MatchString(manifest.KernelVersion) {
		problems = append(problems, "Buildroot and kernel versions must be numeric dotted versions, optionally prefixed by v")
	}
	if len(manifest.HardwareRevisions) == 0 || len(manifest.HardwareRevisions) > 16 {
		problems = append(problems, "hardware_revisions must list 1 to 16 exact revisions")
	}
	revisions := make(map[string]bool, len(manifest.HardwareRevisions))
	for _, revision := range manifest.HardwareRevisions {
		if !validHardwareRevision(revision) || revisions[revision] {
			problems = append(problems, "hardware_revisions contains an invalid or duplicate revision")
			break
		}
		revisions[revision] = true
	}
	if len(manifest.Artifacts) == 0 || len(manifest.Artifacts) > maxArtifacts {
		problems = append(problems, "artifacts must contain 1 to 16 entries")
	}
	seen := make(map[string]bool, len(manifest.Artifacts))
	var totalSize int64
	for _, artifact := range manifest.Artifacts {
		if !validArtifactName(artifact.Name) || seen[artifact.Name] {
			problems = append(problems, "artifacts contains an invalid or duplicate filename")
			break
		}
		seen[artifact.Name] = true
		if !rolePattern.MatchString(artifact.Role) {
			problems = append(problems, "artifacts contains an invalid role")
			break
		}
		if artifact.SizeBytes <= 0 || artifact.SizeBytes > maxArtifactSize || !digestPattern.MatchString(artifact.SHA256) {
			problems = append(problems, "artifacts contains an invalid size or SHA-256 digest")
			break
		}
		if totalSize > maxBundleSize-artifact.SizeBytes {
			problems = append(problems, "combined artifact size exceeds 2 GiB")
			break
		}
		totalSize += artifact.SizeBytes
	}
	if len(manifest.SigningKeyID) != len("sha256:")+64 || !strings.HasPrefix(manifest.SigningKeyID, "sha256:") || !digestPattern.MatchString(strings.TrimPrefix(manifest.SigningKeyID, "sha256:")) {
		problems = append(problems, "signing_key_id must be a SHA-256 public-key fingerprint")
	}
	if len(problems) == 0 {
		return nil
	}
	return errors.New(strings.Join(problems, "; "))
}

func decodeStrict(data []byte, destination any) error {
	if err := rejectDuplicateKeys(data); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func rejectDuplicateKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSON(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanJSON(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]bool)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] {
				return errors.New("duplicate or invalid JSON object key")
			}
			seen[key] = true
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSON(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func hashRegularArtifact(directory, name string, expectedSize int64) (int64, string, error) {
	rootInfo, err := os.Lstat(directory)
	if err != nil || !rootInfo.IsDir() || rootInfo.Mode()&os.ModeSymlink != 0 {
		return 0, "", errors.New("artifact directory is not a real directory")
	}
	path := filepath.Join(directory, name)
	before, err := os.Lstat(path)
	if err != nil || !before.Mode().IsRegular() || before.Mode()&os.ModeSymlink != 0 {
		return 0, "", errors.New("artifact is not a regular file")
	}
	if before.Size() < 0 || before.Size() > maxArtifactSize {
		return before.Size(), "", errors.New("artifact exceeds size limit")
	}
	if before.Size() != expectedSize {
		return before.Size(), "", nil
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return 0, "", errors.New("artifact changed during open")
	}
	state := sha256.New()
	count, err := io.Copy(state, file)
	if err != nil {
		return count, "", err
	}
	after, err := file.Stat()
	if err != nil || count != opened.Size() || after.Size() != opened.Size() || !after.ModTime().Equal(opened.ModTime()) {
		return count, "", errors.New("artifact changed while reading")
	}
	return count, hexHash(state), nil
}

func hexHash(state hash.Hash) string { return hex.EncodeToString(state.Sum(nil)) }

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func validArtifactName(name string) bool {
	return name != "." && name != ".." && filenamePattern.MatchString(name) && !strings.ContainsAny(name, `/\\:`) && filepath.Base(name) == name
}

func validHardwareRevision(revision string) bool {
	if !identifierPattern.MatchString(revision) {
		return false
	}
	switch revision {
	case "all", "any", "unknown":
		return false
	default:
		return true
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
