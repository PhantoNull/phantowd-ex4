// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package storagerefs

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectFindsLegacyVolumeReferencesWithoutReturningSourceLines(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o700); err != nil {
		t.Fatal(err)
	}
	input := "mount=/mnt/HD/HD_b2 share=Volume_2 secret=fixture-secret\n"
	if err := os.WriteFile(filepath.Join(root, "etc", "exports"), []byte(input), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "fixture-secret") || strings.Contains(string(encoded), "mount=") {
		t.Fatalf("source-line content leaked into report: %s", encoded)
	}
	if len(report.Findings) != 3 {
		t.Fatalf("expected three categorized references, got %+v", report.Findings)
	}
	seen := make(map[string]bool)
	for _, finding := range report.Findings {
		seen[finding.Kind+"="+finding.Reference] = true
	}
	for _, expected := range []string{
		"legacy-data-mount=/mnt/HD/HD_b2",
		"legacy-hd-volume-token=HD_b2",
		"legacy-volume-name=Volume_2",
	} {
		if !seen[expected] {
			t.Errorf("missing categorized reference %q in %+v", expected, report.Findings)
		}
	}
}

func TestInspectFindsReferencesEmbeddedInBinaryFiles(t *testing.T) {
	root := t.TempDir()
	data := []byte{0x7f, 'E', 'L', 'F', 0, 0xff, '/', 'd', 'e', 'v', '/', 's', 'd', 'c', '1', 0}
	if err := os.WriteFile(filepath.Join(root, "legacy-daemon"), data, 0o700); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 1 || len(report.Findings) != 1 || report.Findings[0].Kind != "linux-disk-device" || report.Findings[0].Reference != "/dev/sdc1" {
		t.Fatalf("binary literal was not detected: %+v", report)
	}
}

func TestInspectDoesNotFollowSymlinks(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.conf")
	if err := os.WriteFile(outside, []byte("/mnt/HD/HD_a2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked.conf")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.SymlinksSkipped != 1 || report.FilesScanned != 0 || len(report.Findings) != 0 {
		t.Fatalf("symlink target was scanned: %+v", report)
	}
}

func TestInspectSkipsOversizedFiles(t *testing.T) {
	root := t.TempDir()
	large := filepath.Join(root, "oversized")
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxFileBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.SkippedLargeFiles != 1 || report.FilesScanned != 0 || len(report.Findings) != 0 {
		t.Fatalf("oversized file was not skipped: %+v", report)
	}
}

func TestInspectReportsScannedByteCoverage(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "empty"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	contents := []byte("Volume_2\n")
	if err := os.WriteFile(filepath.Join(root, "manifest"), contents, 0o600); err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(root)
	if err != nil {
		t.Fatal(err)
	}
	if report.FilesScanned != 2 || report.EmptyFilesScanned != 1 || report.BytesScanned != int64(len(contents)) {
		t.Fatalf("scan coverage was not reported accurately: %+v", report)
	}
}
