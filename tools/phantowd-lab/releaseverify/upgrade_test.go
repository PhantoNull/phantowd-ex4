// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"strings"
	"testing"
)

func TestUpgradePrerequisiteUsesAuthenticatedImmutableMetadata(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	verified, report, err := InspectManifest(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || verified == nil || report.ArtifactsChecked {
		t.Fatal("metadata fixture failed")
	}
	for _, test := range []struct {
		current string
		newer   bool
	}{
		{"v0.0.9", true}, {"v0.1.0-rc.1", true}, {"v0.1.0", false},
		{"v0.1.1", false}, {"v999999999999999999.0.0", false},
	} {
		policy := verified.AssessUpgradePrerequisite(test.current)
		if !policy.Evaluated || policy.StrictlyNewer != test.newer || policy.CurrentVersion != test.current ||
			policy.ReleaseVersion != "v0.1.0" || policy.InstallationAuthorized || !test.newer && policy.Finding == "" {
			t.Fatalf("wrong metadata prerequisite: %+v", policy)
		}
	}
	for _, current := range []string{"", "0.1.0", "v00.1.0", "v0.1.0+build", strings.Repeat("v", 129)} {
		policy := verified.AssessUpgradePrerequisite(current)
		if policy.Evaluated || policy.StrictlyNewer || policy.InstallationAuthorized || policy.Finding == "" {
			t.Fatal("invalid current version acquired prerequisite evidence")
		}
		if _, err := InspectUpgrade(nil, nil, nil, "", "", "", "", "", current); err == nil {
			t.Fatal("invalid required version reached metadata readers")
		}
	}
	for _, missing := range []*VerifiedManifest{nil, {}} {
		policy := missing.AssessUpgradePrerequisite("v0.0.9")
		if policy.Evaluated || policy.StrictlyNewer || policy.ReleaseVersion != "" || policy.InstallationAuthorized {
			t.Fatal("unverified metadata acquired prerequisite evidence")
		}
	}
	policy := verified.AssessUpgradePrerequisite("v0.0.9")
	policy.ReleaseVersion = "v99.0.0"
	report.ReleaseVersion = "v99.0.0"
	if again := verified.AssessUpgradePrerequisite("v0.1.0"); again.StrictlyNewer || again.ReleaseVersion != "v0.1.0" {
		t.Fatal("caller mutated authenticated release version")
	}
}

func TestInspectUpgradeRefusesBeforePayloadAndRetainsOtherGates(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	inspect := func(directory, current, installer, revision string, signature []byte) (Report, error) {
		return InspectUpgrade(bytes.NewReader(fixture.manifest), bytes.NewReader(signature), fixture.publicKey, directory, "wd-my-cloud-ex4", revision, "nightly", installer, current)
	}
	for _, current := range []string{"v0.1.0", "v0.1.1"} {
		report, err := inspect("", current, "v0.1.0", "board-r1", fixture.signature)
		if err != nil || report.UpgradePrerequisite == nil || !report.UpgradePrerequisite.Evaluated ||
			report.UpgradePrerequisite.StrictlyNewer || report.Valid || report.ArtifactsChecked || len(report.Artifacts) != 0 ||
			report.InstallerPolicy == nil || !report.InstallerPolicy.Compatible || report.UpdatePolicy != nil {
			t.Fatalf("non-upgrade crossed payload boundary: %+v err=%v", report, err)
		}
	}
	for _, mutation := range []string{"signature", "target", "installer"} {
		signature := append([]byte(nil), fixture.signature...)
		revision, installer := "board-r1", "v0.1.0"
		switch mutation {
		case "signature":
			signature[0] ^= 1
		case "target":
			revision = "board-r2"
		case "installer":
			installer = "v0.0.9"
		}
		report, err := inspect("", "v0.0.9", installer, revision, signature)
		if err != nil || report.Valid || report.ArtifactsChecked || report.UpgradePrerequisite != nil {
			t.Fatalf("upgrade preflight crossed %s gate: %+v err=%v", mutation, report, err)
		}
	}
	for _, directory := range []string{fixture.directory, ""} {
		report, err := inspect(directory, "v0.0.9", "v0.1.0", "board-r1", fixture.signature)
		if err != nil || report.Valid != (directory != "") || !report.ArtifactsChecked || report.UpgradePrerequisite == nil ||
			!report.UpgradePrerequisite.StrictlyNewer || report.UpgradePrerequisite.InstallationAuthorized ||
			report.InstallationAuthorized || report.HardwareQualified || report.UpdatePolicy != nil {
			t.Fatalf("prerequisite bypassed payload/authority boundary: %+v err=%v", report, err)
		}
	}
}
