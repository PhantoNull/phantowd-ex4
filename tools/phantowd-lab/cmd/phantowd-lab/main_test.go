// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDecodeMCUCommand(t *testing.T) {
	var output bytes.Buffer
	code, err := run([]string{"decode-mcu", "fa 23 00 00 00 00 fb"}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"PWRPush"`) || !strings.Contains(output.String(), `"unknown-not-validated"`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

func TestReplayHexCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.hex")
	if err := os.WriteFile(path, []byte("# synthetic\nfa 23 00 00 00 00 fb\nfa 2a 00 00 00 00 fb # release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"replay-mcu", "--format", "hex", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"frames": 2`) || !strings.Contains(output.String(), `"power": false`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

func TestInspectRescueCommandRedactsIdentity(t *testing.T) {
	fixture := make([]byte, 2048+4)
	copy(fixture[0:20], "00:11:22:33:44:55")
	copy(fixture[0x1c:0x30], "02:12:23:34:45:56")
	binary.LittleEndian.PutUint32(fixture[0x14:], 4)
	binary.LittleEndian.PutUint32(fixture[0x18:], 0x04030201)
	copy(fixture[0x32:], []byte{0x55, 0xaa, 'L', 'i', 'g', 'R', 'e', 's', 'c', 'u', 'r', 'e'})
	copy(fixture[0x3e:], []byte{0, 0x14, 0, 1, 1})
	copy(fixture[2048:], []byte{1, 2, 3, 4})
	path := filepath.Join(t.TempDir(), "rescue.bin")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-rescue", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"identity_redacted": true`) ||
		!strings.Contains(output.String(), `"identity_fields_valid": true`) ||
		strings.Contains(output.String(), "00:11:22") ||
		strings.Contains(output.String(), "02:12:23") {
		t.Fatalf("identity was not redacted: %s", output.String())
	}
}

func TestInspectRescueCommandRejectsIncompleteIdentity(t *testing.T) {
	fixture := make([]byte, 2048+4)
	copy(fixture[0:20], "02:11:22:33:44:55")
	binary.LittleEndian.PutUint32(fixture[0x14:], 4)
	binary.LittleEndian.PutUint32(fixture[0x18:], 0x04030201)
	copy(fixture[0x32:], []byte{0x55, 0xaa, 'L', 'i', 'g', 'R', 'e', 's', 'c', 'u', 'r', 'e'})
	copy(fixture[0x3e:], []byte{0, 0x14, 0, 1, 1})
	copy(fixture[2048:], []byte{1, 2, 3, 4})
	path := filepath.Join(t.TempDir(), "rescue-invalid-identity.bin")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-rescue", path}, &output)
	if err != nil || code != 2 {
		t.Fatalf("code=%d err=%v; expected invalid parsed input", code, err)
	}
	if !strings.Contains(output.String(), `"identity_fields_valid": false`) || strings.Contains(output.String(), "02:11:22") {
		t.Fatalf("invalid identity was not rejected safely: %s", output.String())
	}
}

func TestInventoryRootfsCommandDoesNotExposeHostRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "release"), []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inventory-rootfs", "--summary", root}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if strings.Contains(output.String(), filepath.ToSlash(root)) || !strings.Contains(output.String(), `"regular_files": 1`) {
		t.Fatalf("unexpected rootfs inventory output: %s", output.String())
	}
}

func TestScanStorageReferencesCommandReportsOnlyRelativeMatches(t *testing.T) {
	root := t.TempDir()
	configDir := filepath.Join(root, "config")
	if err := os.Mkdir(configDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(configDir, "mounts"), []byte("data=/mnt/HD/HD_b2 secret=fixture-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"scan-storage-refs", root}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"kind": "legacy-data-mount"`) ||
		!strings.Contains(output.String(), `"path": "config/mounts"`) ||
		strings.Contains(output.String(), filepath.ToSlash(root)) ||
		strings.Contains(output.String(), "fixture-secret") {
		t.Fatalf("unexpected storage-reference report: %s", output.String())
	}
}

func TestInspectStorageInventoryCommandEmitsRedactedJSONAndRejectsAmbiguity(t *testing.T) {
	fixture := `{"format":"phantowd-storage-inventory","schema_version":1,"disks":[{"id":"disk-a","wwn":"fixture-wwn-001","serial":"fixture-serial-001","bay":1,"device":"/dev/sda"}],"partitions":[{"id":"partition-a","disk_id":"disk-a","number":2,"partuuid":"fixture-partuuid-001"}],"volumes":[{"id":"volume-a","logical_volume_number":1,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","md_uuid":"fixture-md-uuid-001","member_partition_ids":["partition-a"]}]}`
	path := filepath.Join(t.TempDir(), "inventory.json")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-storage-inventory", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid inventory: code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"identity_material_redacted": true`) ||
		!strings.Contains(output.String(), `"historical_data_mount": "/mnt/HD/HD_a2"`) ||
		strings.Contains(output.String(), "fixture-") || strings.Contains(output.String(), filepath.ToSlash(filepath.Dir(path))) {
		t.Fatalf("unexpected inventory output or leaked identity/path: %s", output.String())
	}

	ambiguous := strings.Replace(fixture, `"member_partition_ids":["partition-a"]}]`,
		`"member_partition_ids":["partition-a"]},{"id":"volume-b","logical_volume_number":2,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","member_partition_ids":["partition-a"]}]`, 1)
	if err := os.WriteFile(path, []byte(ambiguous), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	code, err = run([]string{"inspect-storage-inventory", path}, &output)
	if err != nil || code != 2 {
		t.Fatalf("ambiguous inventory: code=%d err=%v; expected invalid report", code, err)
	}
	if !strings.Contains(output.String(), `"valid": false`) || strings.Contains(output.String(), "fixture-") {
		t.Fatalf("invalid inventory was not safely redacted: %s", output.String())
	}
}

func TestPlanStorageInventoryCommandIsRedactedAndDryRunOnly(t *testing.T) {
	fixture := `{"format":"phantowd-storage-assessment","schema_version":1,"legacy_volume_metadata_state":"not_collected","inventory":{"format":"phantowd-storage-inventory","schema_version":1,"disks":[{"id":"disk-a","wwn":"fixture-wwn-001","serial":"fixture-serial-001","bay":1,"device":"/dev/sda"}],"partitions":[{"id":"partition-a","disk_id":"disk-a","number":2,"partuuid":"fixture-partuuid-001"}],"volumes":[{"id":"volume-a","logical_volume_number":1,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","md_uuid":"fixture-md-uuid-001","member_partition_ids":["partition-a"]}]}}`
	path := filepath.Join(t.TempDir(), "assessment.json")
	if err := os.WriteFile(path, []byte(fixture), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"plan-storage-inventory", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("candidate assessment: code=%d err=%v", code, err)
	}
	for _, expected := range []string{`"classification": "candidate"`, `"compatibility_qualified": false`, `"can_execute": false`, `"mode": "dry-run"`, `"operations": []`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in assessment: %s", expected, output.String())
		}
	}
	for _, secret := range []string{"fixture-wwn-001", "fixture-serial-001", "fixture-partuuid-001", "fixture-fs-uuid-001", "fixture-md-uuid-001", "/dev/sda"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("assessment leaked %q: %s", secret, output.String())
		}
	}

	damaged := strings.Replace(fixture, `"legacy_volume_metadata_state":"not_collected"`, `"legacy_volume_metadata_state":"absent"`, 1)
	if err := os.WriteFile(path, []byte(damaged), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	code, err = run([]string{"plan-storage-inventory", path}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"classification": "damaged"`) {
		t.Fatalf("damaged assessment: code=%d err=%v output=%s", code, err, output.String())
	}
}

func TestRejectsNonRegularInput(t *testing.T) {
	if _, _, err := openRegular(t.TempDir()); err == nil {
		t.Fatal("directory input was accepted")
	}
}

func TestInvalidCommand(t *testing.T) {
	if code, err := run([]string{"write-flash"}, &bytes.Buffer{}); code == 0 || err == nil {
		t.Fatal("unknown mutation command was accepted")
	}
}
