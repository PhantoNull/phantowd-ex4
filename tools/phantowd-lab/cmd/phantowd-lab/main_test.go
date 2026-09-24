// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"hash/crc32"
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

func TestInspectGPTImageCommandIsReadOnlyAndDoesNotQualifyWDCompatibility(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic.img")
	if err := os.WriteFile(path, syntheticGPTImageForCommand(), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-gpt-image", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid synthetic GPT: code=%d err=%v output=%s", code, err, output.String())
	}
	for _, expected := range []string{`"status": "valid-gpt"`, `"wd_compatibility": "unqualified"`, `"block_device_opened": false`, `"mutations_performed": false`, `"assembly_performed": false`, `"mount_performed": false`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report: %s", expected, output.String())
		}
	}
	if strings.Contains(output.String(), filepath.ToSlash(path)) || strings.Contains(output.String(), "fixture-disk-guid") {
		t.Fatalf("report leaked input path or identity: %s", output.String())
	}

	if err := os.WriteFile(path, make([]byte, 4096), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	code, err = run([]string{"inspect-gpt-image", path}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"status": "unsupported"`) {
		t.Fatalf("non-GPT input: code=%d err=%v output=%s", code, err, output.String())
	}
}

func TestInspectExtPartitionCommandIsReadOnlyAndGeneric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-ext.img")
	if err := os.WriteFile(path, syntheticGPTImageForCommand(), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-ext-partition", path, "1"}, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid synthetic ext partition: code=%d err=%v output=%s", code, err, output.String())
	}
	for _, expected := range []string{`"status": "ext-superblock-candidate"`, `"filesystem_family": "ext-family"`, `"filesystem_bytes": 2048`, `"wd_compatibility": "unqualified"`, `"block_device_opened": false`, `"mutations_performed": false`, `"mount_performed": false`, `"superblock_checksum_status": "not-advertised-or-unknown"`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report: %s", expected, output.String())
		}
	}
	for _, secret := range []string{filepath.ToSlash(path), "00112233445566778899aabbccddeeff", "EXT4_PRIVATE_LABEL"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("report leaked %q: %s", secret, output.String())
		}
	}

	output.Reset()
	code, err = run([]string{"inspect-ext-partition", path, "2"}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"status": "unsupported"`) {
		t.Fatalf("missing GPT partition: code=%d err=%v output=%s", code, err, output.String())
	}
	if code, err = run([]string{"inspect-ext-partition", path, "129"}, &bytes.Buffer{}); code != 1 || err == nil {
		t.Fatalf("out-of-range partition number: code=%d err=%v", code, err)
	}
}

func TestInspectMDV12PartitionCommandIsReadOnlyAndGeneric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-md.img")
	fixture := syntheticGPTImageForCommand()
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-md-v1.2-partition", path, "1"}, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid synthetic md partition: code=%d err=%v output=%s", code, err, output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(fixture) {
		t.Fatalf("image changed during inspection: err=%v", err)
	}
	for _, expected := range []string{`"status": "md-v1.2-superblock-candidate"`, `"metadata_version": "1.2"`, `"superblock_checksum_status": "valid"`, `"raid_disks": 2`, `"member_number": 0`, `"wd_compatibility": "unqualified"`, `"block_device_opened": false`, `"mutations_performed": false`, `"assembly_performed": false`, `"mount_performed": false`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report: %s", expected, output.String())
		}
	}
	for _, secret := range []string{filepath.ToSlash(path), "MD_PRIVATE_ARRAY_ID", "MD_PRIVATE_MEMBER_ID", "PRIVATE_MD_SET_NAME"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("report leaked %q: %s", secret, output.String())
		}
	}
	if code, err = run([]string{"inspect-md-v1.2-partition", path, "129"}, &bytes.Buffer{}); code != 1 || err == nil {
		t.Fatalf("out-of-range partition number: code=%d err=%v", code, err)
	}
}

func TestInspectMDV090ComponentCommandIsReadOnlyAndGeneric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-md-component.img")
	fixture := syntheticMDV090ComponentForCommand()
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-md-v0.90-component", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid synthetic md component: code=%d err=%v output=%s", code, err, output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(fixture) {
		t.Fatalf("image changed during inspection: err=%v", err)
	}
	for _, expected := range []string{`"status": "md-v0.90-superblock-candidate"`, `"metadata_version": "0.90"`, `"superblock_checksum_status": "valid"`, `"raid_disks": 2`, `"member_number": 0`, `"wd_compatibility": "unqualified"`, `"block_device_opened": false`, `"mutations_performed": false`, `"assembly_performed": false`, `"mount_performed": false`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report: %s", expected, output.String())
		}
	}
	for _, secret := range []string{filepath.ToSlash(path), "PRIVATE_ARRAY_ID", "/dev/sda"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("report leaked %q: %s", secret, output.String())
		}
	}
	if code, err = run([]string{"inspect-md-v0.90-component", path, "extra"}, &bytes.Buffer{}); code != 1 || err == nil {
		t.Fatalf("extra argument: code=%d err=%v", code, err)
	}
}

func TestInspectMDV090GPTPartitionCommandIsReadOnlyAndGeneric(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-md-disk.img")
	fixture := syntheticGPTImageWithMDV090()
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-md-v0.90-partition", path, "1"}, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid synthetic md GPT partition: code=%d err=%v output=%s", code, err, output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(fixture) {
		t.Fatalf("disk image changed during inspection: err=%v", err)
	}
	for _, expected := range []string{`"status": "md-v0.90-superblock-candidate"`, `"partition_number": 1`, `"metadata_version": "0.90"`, `"superblock_checksum_status": "valid"`, `"wd_compatibility": "unqualified"`, `"block_device_opened": false`, `"mutations_performed": false`, `"assembly_performed": false`, `"mount_performed": false`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report: %s", expected, output.String())
		}
	}
	for _, secret := range []string{filepath.ToSlash(path), "PRIVATE_ARRAY_ID", "/dev/sda"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("report leaked %q: %s", secret, output.String())
		}
	}
	output.Reset()
	code, err = run([]string{"inspect-md-v0.90-partition", path, "2"}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"status": "unsupported"`) {
		t.Fatalf("missing GPT partition: code=%d err=%v output=%s", code, err, output.String())
	}
}

func TestInspectStorageImageAggregatesReadOnlyPartitionObservations(t *testing.T) {
	path := filepath.Join(t.TempDir(), "synthetic-storage-disk.img")
	fixture := syntheticGPTImageWithMDV090()
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-storage-image", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid synthetic storage image: code=%d err=%v output=%s", code, err, output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(fixture) {
		t.Fatalf("disk image changed during inspection: err=%v", err)
	}
	for _, expected := range []string{`"gpt_status": "valid-gpt"`, `"partition_observations"`, `"partition_number": 1`, `"status": "md-v0.90-superblock-candidate"`, `"status": "not-ext-superblock"`, `"status": "no-md-v1.2-superblock"`, `"wd_compatibility": "unqualified"`, `"block_device_opened": false`, `"mutations_performed": false`, `"assembly_performed": false`, `"mount_performed": false`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report: %s", expected, output.String())
		}
	}
	for _, secret := range []string{filepath.ToSlash(path), "synthetic-partition", "PRIVATE_ARRAY_ID", "/dev/sda"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("report leaked %q: %s", secret, output.String())
		}
	}

	badPath := filepath.Join(t.TempDir(), "not-gpt.img")
	if err := os.WriteFile(badPath, []byte("not a GPT disk image"), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	code, err = run([]string{"inspect-storage-image", badPath}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"partition_observations": []`) {
		t.Fatalf("invalid GPT report: code=%d err=%v output=%s", code, err, output.String())
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

func syntheticGPTImageForCommand() []byte {
	const sector = 512
	const sectors = 64
	const entrySize = 128
	image := make([]byte, sector*sectors)
	image[510], image[511] = 0x55, 0xaa
	image[446+4] = 0xee
	binary.LittleEndian.PutUint32(image[446+8:], 1)
	binary.LittleEndian.PutUint32(image[446+12:], sectors-1)

	primaryEntries := image[2*sector : 2*sector+entrySize]
	copy(primaryEntries[:16], []byte{0xaf, 0x3d, 0xc6, 0x0f, 0x83, 0x84, 0x72, 0x47, 0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4})
	copy(primaryEntries[16:32], []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})
	binary.LittleEndian.PutUint64(primaryEntries[32:40], 3)
	binary.LittleEndian.PutUint64(primaryEntries[40:48], 60)
	backupEntries := image[62*sector : 62*sector+entrySize]
	copy(backupEntries, primaryEntries)
	entriesCRC := crc32.ChecksumIEEE(primaryEntries)
	putGPTHeaderForCommand(image[sector:2*sector], 1, sectors-1, 2, entriesCRC)
	putGPTHeaderForCommand(image[63*sector:], sectors-1, 1, 62, entriesCRC)
	putExtSuperblockForCommand(image)
	putMDV12SuperblockForCommand(image)
	return image
}

func syntheticMDV090ComponentForCommand() []byte {
	image := make([]byte, 1024*1024)
	superblockOffset := len(image) - 64*1024
	sb := image[superblockOffset : superblockOffset+4096]
	binary.LittleEndian.PutUint32(sb[0:4], 0xa92b4efc)
	binary.LittleEndian.PutUint32(sb[4:8], 0)
	binary.LittleEndian.PutUint32(sb[8:12], 90)
	copy(sb[20:24], []byte("PRIV"))
	binary.LittleEndian.PutUint32(sb[28:32], 1)
	binary.LittleEndian.PutUint32(sb[36:40], 2)
	binary.LittleEndian.PutUint32(sb[40:44], 2)
	copy(sb[52:56], []byte("ATE_"))
	copy(sb[56:60], []byte("ARRA"))
	copy(sb[60:64], []byte("Y_ID"))
	binary.LittleEndian.PutUint32(sb[156:160], 42)
	binary.LittleEndian.PutUint32(sb[992*4:992*4+4], 0)
	binary.LittleEndian.PutUint32(sb[992*4+12:992*4+16], 0)
	var sum uint64
	for offset := 0; offset+4 <= len(sb); offset += 4 {
		if offset != 152 {
			sum += uint64(binary.LittleEndian.Uint32(sb[offset : offset+4]))
		}
	}
	binary.LittleEndian.PutUint32(sb[152:156], uint32(sum)+uint32(sum>>32))
	return image
}

func syntheticGPTImageWithMDV090() []byte {
	const sector = 512
	const sectors = 2048
	const entrySize = 128
	image := make([]byte, sector*sectors)
	image[510], image[511] = 0x55, 0xaa
	image[446+4] = 0xee
	binary.LittleEndian.PutUint32(image[446+8:], 1)
	binary.LittleEndian.PutUint32(image[446+12:], sectors-1)

	const firstLBA = 64
	const lastLBA = sectors - 64
	primaryEntries := image[2*sector : 2*sector+entrySize]
	copy(primaryEntries[:16], []byte{0x0f, 0x88, 0x9d, 0xa1, 0xfc, 0x05, 0x3b, 0x4d, 0xa0, 0x06, 0x74, 0x3f, 0x0f, 0x84, 0x91, 0x1e})
	copy(primaryEntries[16:32], []byte("synthetic-partition"))
	binary.LittleEndian.PutUint64(primaryEntries[32:40], firstLBA)
	binary.LittleEndian.PutUint64(primaryEntries[40:48], lastLBA)
	backupEntriesLBA := uint64(sectors - 2)
	backupEntries := image[int(backupEntriesLBA)*sector : int(backupEntriesLBA)*sector+entrySize]
	copy(backupEntries, primaryEntries)
	entriesCRC := crc32.ChecksumIEEE(primaryEntries)
	putGPTHeaderForCommandWithBounds(image[sector:2*sector], 1, sectors-1, 2, entriesCRC, 3, sectors-3)
	putGPTHeaderForCommandWithBounds(image[(sectors-1)*sector:], sectors-1, 1, backupEntriesLBA, entriesCRC, 3, sectors-3)

	component := syntheticMDV090ComponentForCommand()
	componentSuperblock := component[len(component)-64*1024 : len(component)-64*1024+4096]
	partitionBytes := (lastLBA - firstLBA + 1) * sector
	partitionSuperblockOffset := int(partitionBytes&^(64*1024-1)) - 64*1024
	partitionStart := int(firstLBA) * sector
	copy(image[partitionStart+partitionSuperblockOffset:partitionStart+partitionSuperblockOffset+4096], componentSuperblock)
	return image
}

func putMDV12SuperblockForCommand(image []byte) {
	const partitionStartLBA = 3
	start := partitionStartLBA*512 + 4096
	superblock := image[start : start+260]
	binary.LittleEndian.PutUint32(superblock[0:4], 0xa92b4efc)
	binary.LittleEndian.PutUint32(superblock[4:8], 1)
	copy(superblock[16:32], []byte("MD_PRIVATE_ARRAY_ID"))
	copy(superblock[32:64], []byte("PRIVATE_MD_SET_NAME"))
	binary.LittleEndian.PutUint32(superblock[72:76], 1)
	binary.LittleEndian.PutUint32(superblock[92:96], 2)
	binary.LittleEndian.PutUint64(superblock[128:136], 16)
	binary.LittleEndian.PutUint64(superblock[136:144], 32)
	binary.LittleEndian.PutUint64(superblock[144:152], 8)
	copy(superblock[168:184], []byte("MD_PRIVATE_MEMBER_ID"))
	binary.LittleEndian.PutUint64(superblock[200:208], 5)
	binary.LittleEndian.PutUint32(superblock[220:224], 2)
	binary.LittleEndian.PutUint16(superblock[256:258], 0)
	binary.LittleEndian.PutUint16(superblock[258:260], 1)
	binary.LittleEndian.PutUint32(superblock[216:220], 0)
	var sum uint64
	for offset := 0; offset+4 <= len(superblock); offset += 4 {
		sum += uint64(binary.LittleEndian.Uint32(superblock[offset : offset+4]))
	}
	if len(superblock)%4 == 2 {
		sum += uint64(binary.LittleEndian.Uint16(superblock[len(superblock)-2:]))
	}
	binary.LittleEndian.PutUint32(superblock[216:220], uint32(sum)+uint32(sum>>32))
}

func putExtSuperblockForCommand(image []byte) {
	const sector = 512
	start := 3*sector + 1024
	superblock := image[start : start+1024]
	binary.LittleEndian.PutUint32(superblock[0:4], 4)
	binary.LittleEndian.PutUint32(superblock[4:8], 2)
	binary.LittleEndian.PutUint32(superblock[12:16], 1)
	binary.LittleEndian.PutUint32(superblock[20:24], 1)
	binary.LittleEndian.PutUint32(superblock[24:28], 0)
	binary.LittleEndian.PutUint32(superblock[32:36], 2)
	binary.LittleEndian.PutUint32(superblock[40:44], 4)
	binary.LittleEndian.PutUint16(superblock[56:58], 0xef53)
	binary.LittleEndian.PutUint16(superblock[58:60], 1)
	binary.LittleEndian.PutUint32(superblock[76:80], 1)
	binary.LittleEndian.PutUint32(superblock[92:96], 4)
	binary.LittleEndian.PutUint32(superblock[96:100], 0x40)
	copy(superblock[104:120], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	copy(superblock[120:136], []byte("EXT4_PRIVATE_LABEL"))
}

func putGPTHeaderForCommand(header []byte, currentLBA, backupLBA, entriesLBA uint64, entriesCRC uint32) {
	putGPTHeaderForCommandWithBounds(header, currentLBA, backupLBA, entriesLBA, entriesCRC, 3, 61)
}

func putGPTHeaderForCommandWithBounds(header []byte, currentLBA, backupLBA, entriesLBA uint64, entriesCRC uint32, firstUsableLBA, lastUsableLBA uint64) {
	copy(header[:8], "EFI PART")
	binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
	binary.LittleEndian.PutUint32(header[12:16], 92)
	binary.LittleEndian.PutUint64(header[24:32], currentLBA)
	binary.LittleEndian.PutUint64(header[32:40], backupLBA)
	binary.LittleEndian.PutUint64(header[40:48], firstUsableLBA)
	binary.LittleEndian.PutUint64(header[48:56], lastUsableLBA)
	copy(header[56:72], []byte{0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x10})
	binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
	binary.LittleEndian.PutUint32(header[80:84], 1)
	binary.LittleEndian.PutUint32(header[84:88], 128)
	binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
	binary.LittleEndian.PutUint32(header[16:20], 0)
	binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:92]))
}
