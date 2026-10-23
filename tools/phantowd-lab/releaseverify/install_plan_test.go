// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"crypto/ed25519"
	"io"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestInstallationPreviewVerifiesBytesButRefusesUnqualifiedPlacement(t *testing.T) {
	payload := []byte("synthetic install candidate")
	f := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, payload)
	plan, err := PreviewInstallation(bytes.NewReader(f.manifest), bytes.NewReader(f.signature), f.publicKey,
		f.directory, "wd-my-cloud-ex4", "board-r1", "nightly", "v0.1.0", "v0.0.9")
	if err != nil || !plan.Verification.Valid || plan.Mode != "verify-only" || plan.Status != "refused" || plan.InstallationAuthorized || len(plan.WriteOperations) != 0 {
		t.Fatal("verified bytes became an installation permission", plan, err)
	}
	if len(plan.LogicalPayloads) != 1 || plan.LogicalPayloads[0].Name != "rootfs.swu" || plan.LogicalPayloads[0].Role != "swupdate-bundle" || plan.LogicalPayloads[0].SizeBytes != int64(len(payload)) || plan.LogicalPayloads[0].Destination != "unassigned" || len(plan.Blockers) == 0 || !slices.Contains(plan.LayoutReview, "payload-format") {
		t.Fatal("preview lost logical payload or unknown-layout review", plan)
	}
	after, err := os.ReadFile(filepath.Join(f.directory, "rootfs.swu"))
	if err != nil || !bytes.Equal(after, payload) {
		t.Fatal("preview changed input bytes", err)
	}
	entries, err := os.ReadDir(f.directory)
	if err != nil || len(entries) != 1 {
		t.Fatal("preview created state or output files", err)
	}
}

func TestInstallationPreviewNeverPlansPartialOrRejectedInputs(t *testing.T) {
	for _, fault := range []string{"signature", "target", "channel", "payload", "version", "installer"} {
		t.Run(fault, func(t *testing.T) {
			f := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
			revision, channel, installer, current := "board-r1", "nightly", "v0.1.0", "v0.0.9"
			switch fault {
			case "signature":
				f.signature[0] ^= 1
			case "target":
				revision = "board-r2"
			case "channel":
				channel = "stable"
			case "payload":
				if err := os.WriteFile(filepath.Join(f.directory, "rootfs.swu"), []byte("changed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "version":
				current = "v0.1.0"
			case "installer":
				installer = "v0.0.9"
			}
			plan, err := PreviewInstallation(bytes.NewReader(f.manifest), bytes.NewReader(f.signature), f.publicKey,
				f.directory, "wd-my-cloud-ex4", revision, channel, installer, current)
			if err != nil || plan.Verification.Valid || plan.Status != "verification-failed" || len(plan.LogicalPayloads) != 0 || len(plan.WriteOperations) != 0 || plan.InstallationAuthorized {
				t.Fatal("rejected input produced a logical placement", plan, err)
			}
		})
	}
}

func TestInstallationPreviewUnknownInstalledVersionIsNotPristine(t *testing.T) {
	f := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	plan, err := PreviewInstallation(bytes.NewReader(f.manifest), bytes.NewReader(f.signature), f.publicKey,
		f.directory, "wd-my-cloud-ex4", "board-r1", "nightly", "v0.1.0", "")
	if err != nil || !plan.Verification.Valid || plan.Verification.UpgradePrerequisite != nil || plan.Status != "refused" || !slices.Contains(plan.Blockers, "installed_version_unknown") || plan.InstallationAuthorized || len(plan.WriteOperations) != 0 {
		t.Fatal("unknown installed state became a new-install permission", err)
	}
}

type previewUnread struct{ reads int }

func (r *previewUnread) Read([]byte) (int, error) { r.reads++; return 0, io.EOF }

func TestInstallationPreviewAdmitsRequiredVersionsBeforeMetadataIO(t *testing.T) {
	f := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	for _, versions := range [][2]string{{"", "v0.0.9"}, {"invalid", ""}, {"v0.1.0", "invalid"}} {
		reader := &previewUnread{}
		plan, err := PreviewInstallation(reader, reader, f.publicKey, f.directory,
			"wd-my-cloud-ex4", "board-r1", "nightly", versions[0], versions[1])
		if err == nil || reader.reads != 0 || plan.Format != "" {
			t.Fatal("invalid required version reached metadata or produced a partial plan", reader.reads, err)
		}
	}
}

func TestInstallationPreviewDoesNotShareCallerMutablePolicy(t *testing.T) {
	f := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	preview := func() InstallationPreview {
		p, err := PreviewInstallation(bytes.NewReader(f.manifest), bytes.NewReader(f.signature), f.publicKey,
			f.directory, "wd-my-cloud-ex4", "board-r1", "nightly", "v0.1.0", "v0.0.9")
		if err != nil {
			t.Fatal(err)
		}
		return p
	}
	p := preview()
	p.Blockers[0], p.LayoutReview[0], p.LogicalPayloads[0].Destination = "changed", "changed", "changed"
	p.InstallationAuthorized = true
	again := preview()
	if !slices.Contains(again.Blockers, "g8_target_qualification_deferred") || again.LayoutReview[0] != "space-and-wear" || again.LogicalPayloads[0].Destination != "unassigned" || again.InstallationAuthorized {
		t.Fatal("caller changed fixed qualification policy")
	}
}

func TestInstallationPreviewReturnsNoPlanOnSignedStructureError(t *testing.T) {
	f := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	malformed := []byte("{")
	p, err := PreviewInstallation(bytes.NewReader(malformed), bytes.NewReader(ed25519.Sign(f.privateKey, malformed)), f.publicKey,
		f.directory, "wd-my-cloud-ex4", "board-r1", "nightly", "v0.1.0", "v0.0.9")
	if err == nil || p.Format != "" || p.LogicalPayloads != nil || p.InstallationAuthorized {
		t.Fatal("structure error returned a partial plan", err)
	}
}
