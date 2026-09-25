// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"errors"
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
