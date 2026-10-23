// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"crypto/ed25519"
	"errors"
	"io"
)

// InstallationPreview is informational, never an executable transaction or
// installation authority. No device destination or writer exists in this API.
type InstallationPreview struct {
	Format                 string           `json:"format"`
	SchemaVersion          int              `json:"schema_version"`
	Mode                   string           `json:"mode"`
	Status                 string           `json:"status"`
	Verification           Report           `json:"verification"`
	InstallationAuthorized bool             `json:"installation_authorized"`
	WriteOperations        []string         `json:"write_operations"`
	LogicalPayloads        []LogicalPayload `json:"logical_payloads"`
	Blockers               []string         `json:"blockers"`
	LayoutReview           []string         `json:"required_layout_review"`
}

type LogicalPayload struct {
	Name        string `json:"name"`
	Role        string `json:"role"`
	SizeBytes   int64  `json:"size_bytes"`
	Destination string `json:"destination"`
}

// PreviewInstallation reuses signed-input and payload verification. G8 option
// B and the unapproved physical layout always refuse executable write planning.
func PreviewInstallation(manifestReader, signatureReader io.Reader, publicKey ed25519.PublicKey, artifactDirectory, modelID, hardwareRevision, channel, installerVersion, currentVersion string) (InstallationPreview, error) {
	if _, err := CompareVersions(installerVersion, installerVersion); err != nil {
		return InstallationPreview{}, errors.New("installer version must use strict v-prefixed SemVer syntax")
	}
	var report Report
	var err error
	if currentVersion == "" {
		report, err = InspectWithInstallerVersion(manifestReader, signatureReader, publicKey, artifactDirectory, modelID, hardwareRevision, channel, installerVersion)
	} else {
		report, err = InspectUpgrade(manifestReader, signatureReader, publicKey, artifactDirectory, modelID, hardwareRevision, channel, installerVersion, currentVersion)
	}
	if err != nil {
		return InstallationPreview{}, err
	}
	plan := InstallationPreview{
		Format: "phantowd-installation-preview", SchemaVersion: 1, Mode: "verify-only", Status: "refused", Verification: report,
		WriteOperations: []string{}, LogicalPayloads: []LogicalPayload{},
		Blockers:     []string{"g8_target_qualification_deferred", "recovery_unqualified", "installation_layout_unapproved"},
		LayoutReview: []string{"space-and-wear", "boot-and-rescue", "state-data-separation", "per-unit-identity", "power-loss-and-rollback", "payload-format"},
	}
	if !report.Valid {
		plan.Status = "verification-failed"
		plan.Blockers = append([]string{"bundle_verification_failed"}, plan.Blockers...)
		return plan, nil
	}
	if currentVersion == "" {
		plan.Blockers = append(plan.Blockers, "installed_version_unknown")
	}
	for _, artifact := range report.Artifacts {
		plan.LogicalPayloads = append(plan.LogicalPayloads, LogicalPayload{Name: artifact.Name, Role: artifact.Role, SizeBytes: artifact.Expected, Destination: "unassigned"})
	}
	return plan, nil
}
