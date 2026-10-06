// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package storageinventory

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode/utf8"
)

const (
	assessmentFormat  = "phantowd-storage-assessment"
	assessmentVersion = 1
)

type Classification string

const (
	ClassificationCandidate   Classification = "candidate"
	ClassificationAmbiguous   Classification = "ambiguous"
	ClassificationDamaged     Classification = "damaged"
	ClassificationUnsupported Classification = "unsupported"
)

// Assessment is a fixture-only decision preview. Candidate means only that
// this project's synthetic inventory is internally consistent; it is not a
// WD layout compatibility decision and cannot be executed.
type Assessment struct {
	Format                   string          `json:"format"`
	SchemaVersion            int             `json:"schema_version"`
	Classification           Classification  `json:"classification"`
	LegacyMetadataState      string          `json:"legacy_volume_metadata_state"`
	InventoryValid           bool            `json:"inventory_valid"`
	CompatibilityQualified   bool            `json:"compatibility_qualified"`
	IdentityMaterialRedacted bool            `json:"identity_material_redacted"`
	CanExecute               bool            `json:"can_execute"`
	MutationsPerformed       bool            `json:"mutations_performed"`
	AssemblyPerformed        bool            `json:"assembly_performed"`
	MountPerformed           bool            `json:"mount_performed"`
	DiskCount                int             `json:"disk_count"`
	PartitionCount           int             `json:"partition_count"`
	VolumeCount              int             `json:"volume_count"`
	Findings                 []string        `json:"findings"`
	Volumes                  []PlannedVolume `json:"volume_previews"`
	Plan                     DryRunPlan      `json:"plan"`
	Limitations              []string        `json:"limitations"`
}

type PlannedVolume struct {
	LogicalVolumeNumber int    `json:"logical_volume_number"`
	IdentityBasis       string `json:"identity_basis"`
	IdentityFingerprint string `json:"identity_fingerprint"`
}

type DryRunPlan struct {
	Mode           string   `json:"mode"`
	Executable     bool     `json:"executable"`
	Operations     []string `json:"operations"`
	RequiredChecks []string `json:"required_checks"`
}

type assessmentRequest struct {
	Format              string          `json:"format"`
	SchemaVersion       int             `json:"schema_version"`
	LegacyMetadataState string          `json:"legacy_volume_metadata_state"`
	Inventory           json.RawMessage `json:"inventory"`
}

// Assess validates a versioned synthetic assessment envelope and its nested
// inventory. It never probes hardware and never returns source identifiers.
func Assess(input io.Reader) (Assessment, error) {
	assessment := newAssessment()
	data, err := io.ReadAll(io.LimitReader(input, maxInputBytes+1))
	if err != nil {
		return assessment, errors.New("cannot read assessment input")
	}
	if len(data) > maxInputBytes {
		return assessment, fmt.Errorf("assessment exceeds %d-byte limit", maxInputBytes)
	}
	if !utf8.Valid(data) {
		return assessment, errors.New("assessment is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		if strings.Contains(err.Error(), "duplicate JSON object key") {
			assessment.Classification = ClassificationAmbiguous
			assessment.Findings = []string{"duplicate JSON keys make the evidence ambiguous"}
			return assessment, nil
		}
		return assessment, errors.New("assessment is malformed JSON")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil || fields == nil {
		assessment.Classification = ClassificationDamaged
		assessment.Findings = []string{"assessment envelope must be a JSON object"}
		return assessment, nil
	}
	if err := checkObjectKeys(fields, "assessment", "format", "schema_version", "legacy_volume_metadata_state", "inventory"); err != nil {
		assessment.Classification = ClassificationUnsupported
		assessment.Findings = []string{"assessment envelope contains unsupported fields"}
		return assessment, nil
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var request assessmentRequest
	if err := decoder.Decode(&request); err != nil {
		assessment.Classification = ClassificationDamaged
		assessment.Findings = []string{"assessment envelope fields are malformed"}
		return assessment, nil
	}
	if err := requireJSONEOF(decoder); err != nil {
		assessment.Classification = ClassificationDamaged
		assessment.Findings = []string{"assessment envelope fields are malformed"}
		return assessment, nil
	}
	if request.Format != assessmentFormat || request.SchemaVersion != assessmentVersion {
		assessment.Classification = ClassificationUnsupported
		assessment.Findings = []string{"assessment format or schema version is unsupported"}
		return assessment, nil
	}
	assessment.LegacyMetadataState = request.LegacyMetadataState
	switch request.LegacyMetadataState {
	case "not_collected", "absent", "malformed", "present_unqualified":
	default:
		assessment.Classification = ClassificationUnsupported
		assessment.Findings = []string{"legacy metadata evidence state is unsupported"}
		return assessment, nil
	}
	if len(request.Inventory) == 0 || bytes.Equal(bytes.TrimSpace(request.Inventory), []byte("null")) {
		assessment.Classification = ClassificationDamaged
		assessment.Findings = []string{"inventory evidence is missing"}
		return assessment, nil
	}

	inventory, err := Inspect(bytes.NewReader(request.Inventory))
	if err != nil {
		assessment.Classification = classifyInventoryError(err)
		assessment.Findings = []string{"inventory evidence is malformed or unsupported"}
		return assessment, nil
	}
	assessment.InventoryValid = inventory.Valid
	assessment.DiskCount = inventory.DiskCount
	assessment.PartitionCount = inventory.PartitionCount
	assessment.VolumeCount = inventory.VolumeCount
	assessment.Findings = append(assessment.Findings, inventory.Violations...)
	if !inventory.Valid {
		assessment.Classification = classifyViolations(inventory.Violations)
		return assessment, nil
	}

	switch request.LegacyMetadataState {
	case "absent", "malformed":
		assessment.Classification = ClassificationDamaged
		assessment.Findings = []string{"legacy volume metadata is absent or malformed in this synthetic assessment"}
		return assessment, nil
	case "present_unqualified":
		assessment.Classification = ClassificationAmbiguous
		assessment.Findings = []string{"legacy volume metadata is present but its format is not qualified"}
		return assessment, nil
	default:
		assessment.Classification = ClassificationCandidate
		assessment.Findings = []string{"synthetic inventory is internally consistent; WD layout compatibility remains unqualified"}
	}

	for _, volume := range inventory.Volumes {
		assessment.Volumes = append(assessment.Volumes, PlannedVolume{
			LogicalVolumeNumber: volume.LogicalVolumeNumber,
			IdentityBasis:       volume.IdentityBasis,
			IdentityFingerprint: volume.IdentityFingerprint,
		})
	}
	return assessment, nil
}

func newAssessment() Assessment {
	return Assessment{
		Format:                   assessmentFormat,
		SchemaVersion:            assessmentVersion,
		Classification:           ClassificationDamaged,
		IdentityMaterialRedacted: true,
		CanExecute:               false,
		MutationsPerformed:       false,
		AssemblyPerformed:        false,
		MountPerformed:           false,
		Findings:                 []string{},
		Volumes:                  []PlannedVolume{},
		Plan: DryRunPlan{
			Mode:       "dry-run",
			Executable: false,
			Operations: []string{},
			RequiredChecks: []string{
				"qualify the exact WD layout against a verified fixture corpus",
				"verify an independent restorable backup before any migration design",
				"obtain explicit operator review before any future device operation",
			},
		},
		Limitations: []string{
			"candidate means only a structurally valid project-owned synthetic inventory, never WD compatibility support",
			"legacy metadata state is a synthetic fixture assertion, not a WD XML parser or a device observation",
			"raw disk, partition, filesystem, array, serial, WWN, bay and kernel-device identifiers are not returned",
			"this tool reads only the supplied regular file and never probes, assembles, mounts, writes or authorizes storage",
		},
	}
}

func (assessment Assessment) ExitCode() int {
	if assessment.Classification == ClassificationCandidate {
		return 0
	}
	return 2
}

func classifyInventoryError(err error) Classification {
	message := err.Error()
	if strings.Contains(message, "duplicate JSON object key") {
		return ClassificationAmbiguous
	}
	if strings.Contains(message, "unsupported") || strings.Contains(message, "case-mismatched") {
		return ClassificationUnsupported
	}
	return ClassificationDamaged
}

func classifyViolations(violations []string) Classification {
	ambiguous := map[string]bool{
		"disk IDs must be present and unique":                             true,
		"disk bay observations must be unique values from 1 through 4":    true,
		"kernel-device observations must be present and unique":           true,
		"each disk requires at least one stable WWN or serial identifier": true,
		"non-empty WWN identifiers must be valid and unique":              true,
		"non-empty serial identifiers must be valid and unique":           true,
		"partition IDs must be present and unique":                        true,
		"partition references an unknown disk":                            true,
		"partition numbers must be unique within each disk":               true,
		"PARTUUID identifiers must be present, valid, and unique":         true,
		"logical volume numbers must be unique values from 1 through 4":   true,
		"filesystem UUIDs must be present, valid, and unique":             true,
		"non-empty md UUIDs must be valid and unique":                     true,
		"volume member references must be present and unique":             true,
		"volume references an unknown partition":                          true,
		"a partition cannot be assigned to multiple volumes":              true,
	}
	hasAmbiguity := false
	for _, violation := range violations {
		if violation == "unsupported inventory format" || violation == "unsupported inventory schema version" {
			return ClassificationUnsupported
		}
		if ambiguous[violation] {
			hasAmbiguity = true
		}
	}
	if hasAmbiguity {
		return ClassificationAmbiguous
	}
	return ClassificationDamaged
}
