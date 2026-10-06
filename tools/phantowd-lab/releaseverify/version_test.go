// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCompareVersionsSemVerPrecedence(t *testing.T) {
	tests := []struct {
		name string
		a    string
		b    string
		want int
	}{
		{name: "patch increase", a: "v1.2.4", b: "v1.2.3", want: 1},
		{name: "major decrease", a: "v2.0.0", b: "v10.0.0", want: -1},
		{name: "stable outranks prerelease", a: "v1.0.0", b: "v1.0.0-rc.99", want: 1},
		{name: "prerelease precedes stable", a: "v1.0.0-alpha", b: "v1.0.0", want: -1},
		{name: "numeric prerelease ordering", a: "v1.0.0-rc.2", b: "v1.0.0-rc.10", want: -1},
		{name: "numeric prerelease ranks below text", a: "v1.0.0-1", b: "v1.0.0-alpha", want: -1},
		{name: "shorter equal prefix ranks lower", a: "v1.0.0-alpha", b: "v1.0.0-alpha.1", want: -1},
		{name: "arbitrarily large component", a: "v999999999999999999999999.0.0", b: "v999999999999999999999998.999.999", want: 1},
		{name: "equal", a: "v1.2.3-rc.1", b: "v1.2.3-rc.1", want: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := CompareVersions(test.a, test.b)
			if err != nil {
				t.Fatalf("CompareVersions() error = %v", err)
			}
			if got != test.want {
				t.Fatalf("CompareVersions(%q, %q) = %d, want %d", test.a, test.b, got, test.want)
			}
		})
	}
}

func TestCompareVersionsFollowsSemVerPrereleaseSequence(t *testing.T) {
	versions := []string{
		"v1.0.0-alpha",
		"v1.0.0-alpha.1",
		"v1.0.0-alpha.beta",
		"v1.0.0-beta",
		"v1.0.0-beta.2",
		"v1.0.0-beta.11",
		"v1.0.0-rc.1",
		"v1.0.0",
	}
	for index := 1; index < len(versions); index++ {
		order, err := CompareVersions(versions[index-1], versions[index])
		if err != nil || order >= 0 {
			t.Fatalf("SemVer precedence violation: %q compared to %q = %d, err=%v", versions[index-1], versions[index], order, err)
		}
	}
}

func TestCompareVersionsRejectsInvalidSemVer(t *testing.T) {
	for _, version := range []string{
		"1.2.3", "v01.2.3", "v1.02.3", "v1.2.03", "v1.2", "v1.2.3-",
		"v1.2.3-alpha..1", "v1.2.3-01", "v1.2.3+build.1", "v1.2.3/evil",
	} {
		t.Run(version, func(t *testing.T) {
			if _, err := CompareVersions(version, "v1.2.3"); !errors.Is(err, ErrInvalidVersion) {
				t.Fatalf("CompareVersions(%q) error = %v, want ErrInvalidVersion", version, err)
			}
		})
	}
}

func TestCheckMonotonicUpgradeRejectsSameOrOlderVersion(t *testing.T) {
	if err := CheckMonotonicUpgrade("v1.2.3", "v1.2.4"); err != nil {
		t.Fatalf("forward upgrade rejected: %v", err)
	}
	for _, target := range []string{"v1.2.3", "v1.2.2"} {
		if err := CheckMonotonicUpgrade("v1.2.3", target); !errors.Is(err, ErrNotAnUpgrade) {
			t.Errorf("target %q error = %v, want ErrNotAnUpgrade", target, err)
		}
	}
	if err := CheckMonotonicUpgrade("bad-version", "v1.2.4"); !errors.Is(err, ErrInvalidVersion) {
		t.Fatalf("invalid installed version error = %v, want ErrInvalidVersion", err)
	}
}

func TestAssessUpgradeVersionRequiresVerifiedReleaseAndNeverAuthorizesInstall(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	report, err := Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || !report.Valid {
		t.Fatalf("valid synthetic release failed verification: report=%+v err=%v", report, err)
	}

	for _, test := range []struct {
		name           string
		currentVersion string
		wantNewer      bool
	}{
		{name: "forward update", currentVersion: "v0.0.9", wantNewer: true},
		{name: "same version", currentVersion: "v0.1.0", wantNewer: false},
		{name: "downgrade", currentVersion: "v0.2.0", wantNewer: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			assessed := AssessUpgradeVersion(report, test.currentVersion)
			policy := assessed.UpdatePolicy
			if policy == nil || !policy.Evaluated || policy.StrictlyNewer != test.wantNewer {
				t.Fatalf("unexpected policy assessment: %+v", policy)
			}
			if policy.InstallationAuthorized || assessed.InstallationAuthorized || assessed.HardwareQualified {
				t.Fatalf("version comparison authorized installation or hardware: report=%+v", assessed)
			}
		})
	}

	invalid := AssessUpgradeVersion(Report{ReleaseVersion: "v0.1.0"}, "v0.0.9")
	if invalid.UpdatePolicy == nil || invalid.UpdatePolicy.Evaluated || invalid.UpdatePolicy.StrictlyNewer {
		t.Fatalf("unverified report was assessed as an update candidate: %+v", invalid.UpdatePolicy)
	}
	badInstalled := AssessUpgradeVersion(report, "v00.0.9")
	if badInstalled.UpdatePolicy == nil || !badInstalled.UpdatePolicy.Evaluated || badInstalled.UpdatePolicy.StrictlyNewer || !errors.Is(CheckMonotonicUpgrade("v00.0.9", "v0.1.0"), ErrInvalidVersion) {
		t.Fatalf("invalid installed version was accepted: %+v", badInstalled.UpdatePolicy)
	}
}

func TestVerifiedMinimumInstallerPreflight(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	verified, report, err := InspectManifest(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || verified == nil || report.ArtifactsChecked {
		t.Fatalf("metadata-only verification failed: report=%+v err=%v", report, err)
	}
	for _, test := range []struct {
		version    string
		evaluated  bool
		compatible bool
	}{
		{"v0.1.0", true, true}, {"v0.1.1", true, true}, {"v1.0.0-rc.1", true, true},
		{"v0.0.9", true, false}, {"v0.1.0-rc.1", true, false},
		{"v999999999999999999.0.0", true, true},
		{"", false, false}, {"0.1.0", false, false}, {"v00.1.0", false, false},
		{"v0.1.0+build", false, false}, {strings.Repeat("v", 129), false, false},
	} {
		t.Run(test.version, func(t *testing.T) {
			policy := verified.AssessInstallerVersion(test.version)
			if policy.Evaluated != test.evaluated || policy.Compatible != test.compatible || policy.InstallationAuthorized {
				t.Fatalf("unexpected installer prerequisite: %+v", policy)
			}
			if test.evaluated && (policy.InstallerVersion != test.version || policy.MinimumInstaller != "v0.1.0") {
				t.Fatalf("assessment did not retain the authenticated minimum: %+v", policy)
			}
			if !test.compatible && policy.Finding == "" {
				t.Fatal("refusal has no diagnostic")
			}
		})
	}
	for _, invalid := range []*VerifiedManifest{nil, {}} {
		policy := invalid.AssessInstallerVersion("v1.0.0")
		if policy.Evaluated || policy.Compatible || policy.InstallationAuthorized || policy.MinimumInstaller != "" {
			t.Fatalf("unverified manifest granted a prerequisite: %+v", policy)
		}
	}
	policy := verified.AssessInstallerVersion("v0.1.0")
	policy.MinimumInstaller = "v0.0.0"
	if again := verified.AssessInstallerVersion("v0.0.9"); again.Compatible || again.MinimumInstaller != "v0.1.0" {
		t.Fatalf("caller mutated the authenticated minimum: %+v", again)
	}
}

func TestInstallerPreflightRefusesBeforeArtifactReadsAndPreservesOtherGates(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	inspect := func(version, hardware string, signature []byte) (Report, error) {
		return InspectWithInstallerVersion(bytes.NewReader(fixture.manifest), bytes.NewReader(signature), fixture.publicKey, "", "wd-my-cloud-ex4", hardware, "nightly", version)
	}
	old, err := inspect("v0.0.9", "board-r1", fixture.signature)
	if err != nil || old.InstallerPolicy == nil || !old.InstallerPolicy.Evaluated || old.InstallerPolicy.Compatible || old.ArtifactsChecked || old.Valid || len(old.Artifacts) != 0 {
		t.Fatalf("old installer crossed the artifact boundary: report=%+v err=%v", old, err)
	}
	badSignature := append([]byte(nil), fixture.signature...)
	badSignature[0] ^= 1
	for _, test := range []struct {
		hardware  string
		signature []byte
	}{
		{"board-r2", fixture.signature}, {"board-r1", badSignature},
	} {
		got, err := inspect("v1.0.0", test.hardware, test.signature)
		if err != nil || got.InstallerPolicy != nil || got.Valid || got.ArtifactsChecked {
			t.Fatalf("prerequisite assessed before authentication/target: report=%+v err=%v", got, err)
		}
	}
	compatible, err := InspectWithInstallerVersion(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly", "v0.1.0")
	if err != nil || !compatible.Valid || compatible.InstallerPolicy == nil || !compatible.InstallerPolicy.Compatible || compatible.InstallationAuthorized {
		t.Fatalf("compatible verification failed: report=%+v err=%v", compatible, err)
	}
	plain, err := Inspect(bytes.NewReader(fixture.manifest), bytes.NewReader(fixture.signature), fixture.publicKey, fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || !plain.Valid || plain.InstallerPolicy != nil {
		t.Fatalf("integrity-only behavior changed: report=%+v err=%v", plain, err)
	}
	if _, err := InspectWithInstallerVersion(nil, nil, nil, "", "", "", "", "v00.1.0"); err == nil {
		t.Fatal("malformed installer reached metadata readers")
	}
}

func TestInstallerPreflightUsesSignedPrereleaseMinimum(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	var manifest Manifest
	if err := json.Unmarshal(fixture.manifest, &manifest); err != nil {
		t.Fatal(err)
	}
	manifest.MinimumInstaller = "v0.1.0-rc.2"
	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	verified, _, err := InspectManifest(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(fixture.privateKey, data)), fixture.publicKey, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || verified == nil {
		t.Fatalf("signed prerelease minimum was not verified: %v", err)
	}
	for _, test := range []struct {
		version    string
		compatible bool
	}{
		{"v0.1.0-rc.1", false}, {"v0.1.0-rc.2", true},
		{"v0.1.0-rc.10", true}, {"v0.1.0", true}, {"v0.0.99", false},
	} {
		if policy := verified.AssessInstallerVersion(test.version); !policy.Evaluated || policy.Compatible != test.compatible || policy.MinimumInstaller != manifest.MinimumInstaller {
			t.Fatalf("wrong signed prerelease prerequisite: %+v", policy)
		}
	}
}
