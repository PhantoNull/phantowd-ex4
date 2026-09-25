// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectReleaseCLIValidatesSignatureTargetAndPayload(t *testing.T) {
	seed := sha256.Sum256([]byte("synthetic CLI signing key"))
	privateKey := ed25519.NewKeyFromSeed(seed[:])
	publicKey := privateKey.Public().(ed25519.PublicKey)
	keyHash := sha256.Sum256(publicKey)
	payload := []byte("synthetic EX4 release payload")
	payloadHash := sha256.Sum256(payload)
	manifest := map[string]any{
		"format": "phantowd-release-manifest", "schema_version": 1, "product": "phantowd",
		"release_version": "v0.1.0", "channel": "nightly", "model_id": "wd-my-cloud-ex4",
		"hardware_revisions": []string{"board-r1"}, "source_commit": strings.Repeat("b", 40),
		"buildroot_version": "2025.02.18", "kernel_version": "6.18.53", "minimum_installer": "v0.1.0",
		"signing_key_id": "sha256:" + hex.EncodeToString(keyHash[:]),
		"artifacts":      []map[string]any{{"name": "rootfs.swu", "role": "swupdate-bundle", "size_bytes": len(payload), "sha256": hex.EncodeToString(payloadHash[:])}},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	artifactDir := filepath.Join(root, "assets")
	if err := os.Mkdir(artifactDir, 0o700); err != nil {
		t.Fatal(err)
	}
	manifestPath := filepath.Join(root, "manifest.json")
	signaturePath := filepath.Join(root, "manifest.sig")
	publicKeyPath := filepath.Join(root, "release.pub")
	if err := os.WriteFile(manifestPath, manifestBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(signaturePath, ed25519.Sign(privateKey, manifestBytes), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicKeyPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(artifactDir, "rootfs.swu"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"inspect-release", "--manifest", manifestPath, "--signature", signaturePath, "--public-key", publicKeyPath, "--artifacts", artifactDir, "--model", "wd-my-cloud-ex4", "--revision", "board-r1", "--channel", "nightly"}
	var output bytes.Buffer
	code, err := run(args, &output)
	if err != nil || code != 0 {
		t.Fatalf("valid release returned code=%d err=%v output=%s", code, err, output.String())
	}
	if !strings.Contains(output.String(), `"valid": true`) ||
		!strings.Contains(output.String(), `"channel_matched": true`) ||
		!strings.Contains(output.String(), `"installation_authorized": false`) ||
		!strings.Contains(output.String(), `"hardware_qualified": false`) {
		t.Fatalf("unexpected verifier report: %s", output.String())
	}

	upgradeArgs := append(append([]string(nil), args...), "--current-version", "v0.0.9")
	output.Reset()
	code, err = run(upgradeArgs, &output)
	if err != nil || code != 0 || !strings.Contains(output.String(), `"strictly_newer": true`) || !strings.Contains(output.String(), `"installation_authorized": false`) {
		t.Fatalf("optional monotonic version assessment failed safely: code=%d err=%v output=%s", code, err, output.String())
	}

	output.Reset()
	args[len(args)-3] = "board-r2"
	code, err = run(args, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"target_matched": false`) {
		t.Fatalf("non-target revision returned code=%d err=%v output=%s", code, err, output.String())
	}
	args[len(args)-1] = "stable"
	output.Reset()
	code, err = run(args, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"channel_matched": false`) {
		t.Fatalf("non-target channel returned code=%d err=%v output=%s", code, err, output.String())
	}
}

func TestInspectGitHubReleaseRequiresExplicitPinnedInputs(t *testing.T) {
	var output bytes.Buffer
	code, err := run([]string{"inspect-github-release"}, &output)
	if code != 1 || err == nil || !strings.Contains(err.Error(), "--tag VERSION") {
		t.Fatalf("GitHub release command did not fail closed on missing inputs: code=%d err=%v output=%q", code, err, output.String())
	}
}

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

func TestInspectMDV090ImageSetIsReadOnlyGenericAndRedactsPaths(t *testing.T) {
	first := syntheticGPTImageWithMDV090()
	second := syntheticGPTImageWithMDV090()
	setSyntheticMDV090GPTMember(second, 1, 1, 42, 3, 1<<1)
	paths := []string{
		filepath.Join(t.TempDir(), "private-disk-one.img"),
		filepath.Join(t.TempDir(), "private-disk-two.img"),
	}
	fixtures := [][]byte{first, second}
	for index, path := range paths {
		if err := os.WriteFile(path, fixtures[index], 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-md-v0.90-image-set", paths[0], paths[1]}, &output)
	if err != nil || code != 0 {
		t.Fatalf("complete synthetic MD 0.90 image set: code=%d err=%v output=%s", code, err, output.String())
	}
	var report struct {
		Format             string `json:"format"`
		SchemaVersion      int    `json:"schema_version"`
		WDCompatibility    string `json:"wd_compatibility"`
		AssemblyPerformed  bool   `json:"assembly_performed"`
		MountPerformed     bool   `json:"mount_performed"`
		MutationsPerformed bool   `json:"mutations_performed"`
		Comparison         struct {
			SchemaVersion int `json:"schema_version"`
			Arrays        []struct {
				Status          string   `json:"status"`
				ObservedNRDisks []uint32 `json:"observed_nr_disks"`
				Members         []struct {
					MemberState      uint32   `json:"member_state"`
					MemberStateFlags []string `json:"member_state_flags"`
				} `json:"members"`
			} `json:"arrays"`
		} `json:"md_v0_90_comparison"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatalf("decode output: %v: %s", err, output.String())
	}
	if report.Format != "phantowd-md-v0.90-image-set-inspection" || report.SchemaVersion != 1 || report.WDCompatibility != "unqualified" ||
		report.AssemblyPerformed || report.MountPerformed || report.MutationsPerformed || len(report.Comparison.Arrays) != 1 ||
		report.Comparison.SchemaVersion != 2 ||
		report.Comparison.Arrays[0].Status != "metadata-consistent" ||
		len(report.Comparison.Arrays[0].Members) != 2 ||
		report.Comparison.Arrays[0].Members[0].MemberState != 1<<1|1<<2 ||
		strings.Join(report.Comparison.Arrays[0].Members[0].MemberStateFlags, ",") != "active,sync" ||
		report.Comparison.Arrays[0].Members[1].MemberState != 1<<1 ||
		strings.Join(report.Comparison.Arrays[0].Members[1].MemberStateFlags, ",") != "active" ||
		len(report.Comparison.Arrays[0].ObservedNRDisks) != 2 ||
		report.Comparison.Arrays[0].ObservedNRDisks[0] != 2 ||
		report.Comparison.Arrays[0].ObservedNRDisks[1] != 3 {
		t.Fatalf("unexpected generic image-set report: %+v; raw=%s", report, output.String())
	}
	for index, path := range paths {
		after, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(after) != sha256.Sum256(fixtures[index]) {
			t.Fatalf("input image changed during inspection: path=%s err=%v", path, err)
		}
		if strings.Contains(output.String(), filepath.ToSlash(path)) || strings.Contains(output.String(), path) {
			t.Fatalf("report leaked input path %q: %s", path, output.String())
		}
	}
	for _, secret := range []string{"PRIVATE_ARRAY_ID", "PRIVATE_MD_SET_NAME", "/dev/sda"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("report leaked %q: %s", secret, output.String())
		}
	}
	divergentPath := filepath.Join(t.TempDir(), "divergent-disk.img")
	divergent := syntheticGPTImageWithMDV090()
	setSyntheticMDV090GPTMember(divergent, 1, 1, 41, 2, 1<<1|1<<2)
	if err := os.WriteFile(divergentPath, divergent, 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	code, err = run([]string{"inspect-md-v0.90-image-set", paths[0], divergentPath}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"status": "divergent-events"`) {
		t.Fatalf("divergent synthetic image set: code=%d err=%v output=%s", code, err, output.String())
	}
	if code, err = run([]string{"inspect-md-v0.90-image-set"}, &bytes.Buffer{}); code != 1 || err == nil {
		t.Fatalf("missing image paths: code=%d err=%v", code, err)
	}
}

func TestInspectMDV12ImageSetComparesComponentsWithoutWriting(t *testing.T) {
	directory := t.TempDir()
	firstPath := filepath.Join(directory, "first-private-disk.img")
	secondPath := filepath.Join(directory, "second-private-disk.img")
	first := syntheticGPTImageForMDV12Member(0, 0, 41)
	second := syntheticGPTImageForMDV12Member(1, 1, 41)
	for path, image := range map[string][]byte{firstPath: first, secondPath: second} {
		if err := os.WriteFile(path, image, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var output bytes.Buffer
	code, err := run([]string{"inspect-md-v1.2-image-set", firstPath, secondPath}, &output)
	if err != nil || code != 0 {
		t.Fatalf("consistent synthetic image set: code=%d err=%v output=%s", code, err, output.String())
	}
	for _, expected := range []string{`"status": "metadata-consistent"`, `"raid_disks": 2`, `"observed_active_roles": 2`, `"wd_compatibility": "unqualified"`, `"block_device_opened": false`, `"mutations_performed": false`, `"assembly_performed": false`, `"mount_performed": false`} {
		if !strings.Contains(output.String(), expected) {
			t.Fatalf("missing %q in report: %s", expected, output.String())
		}
	}
	for _, secret := range []string{filepath.ToSlash(firstPath), filepath.ToSlash(secondPath), "MD_PRIVATE_ARRAY_ID", "PRIVATE_MD_SET_NAME", "SECOND-MEMBER-ID"} {
		if strings.Contains(output.String(), secret) {
			t.Fatalf("report leaked %q: %s", secret, output.String())
		}
	}
	for path, original := range map[string][]byte{firstPath: first, secondPath: second} {
		after, err := os.ReadFile(path)
		if err != nil || sha256.Sum256(after) != sha256.Sum256(original) {
			t.Fatalf("image %s changed during inspection: err=%v", path, err)
		}
	}

	output.Reset()
	stale := syntheticGPTImageForMDV12Member(1, 1, 42)
	if err := os.WriteFile(secondPath, stale, 0o600); err != nil {
		t.Fatal(err)
	}
	code, err = run([]string{"inspect-md-v1.2-image-set", firstPath, secondPath}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"status": "divergent-events"`) {
		t.Fatalf("divergent event counters: code=%d err=%v output=%s", code, err, output.String())
	}

	output.Reset()
	missingPath := filepath.Join(directory, "valid-disk-without-md.img")
	missing := syntheticGPTImageForCommand()
	clear(missing[3*512+4096 : 3*512+4096+260])
	if err := os.WriteFile(missingPath, missing, 0o600); err != nil {
		t.Fatal(err)
	}
	code, err = run([]string{"inspect-md-v1.2-image-set", firstPath, missingPath}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"status": "incomplete"`) {
		t.Fatalf("incomplete image set: code=%d err=%v output=%s", code, err, output.String())
	}
}

func TestInspectMDV12ImageSetRejectsInvalidUsageAndNonGPTImages(t *testing.T) {
	var output bytes.Buffer
	if code, err := run([]string{"inspect-md-v1.2-image-set"}, &output); code != 1 || err == nil {
		t.Fatalf("accepted empty image set: code=%d err=%v", code, err)
	}
	if code, err := run([]string{"inspect-md-v1.2-image-set", "one", "two", "three", "four", "five"}, &output); code != 1 || err == nil {
		t.Fatalf("accepted too many images: code=%d err=%v", code, err)
	}
	validPath := filepath.Join(t.TempDir(), "valid.img")
	invalidPath := filepath.Join(t.TempDir(), "invalid.img")
	if err := os.WriteFile(validPath, syntheticGPTImageForCommand(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(invalidPath, []byte("not a GPT image"), 0o600); err != nil {
		t.Fatal(err)
	}
	output.Reset()
	if code, err := run([]string{"inspect-md-v1.2-image-set", validPath, invalidPath}, &output); err != nil || code != 2 ||
		!strings.Contains(output.String(), `"gpt_status": "unsupported"`) {
		t.Fatalf("invalid GPT image was not reported conservatively: code=%d err=%v output=%s", code, err, output.String())
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
	binary.LittleEndian.PutUint32(sb[992*4+16:992*4+20], 1<<1|1<<2)
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

func setSyntheticMDV090GPTMember(image []byte, memberNumber, role uint32, events uint64, declaredDevices, memberState uint32) {
	const sector = 512
	const firstLBA = 64
	const lastLBA = 2048 - 64
	partitionBytes := (lastLBA - firstLBA + 1) * sector
	superblockOffset := int(partitionBytes&^(64*1024-1)) - 64*1024
	superblockStart := firstLBA*sector + superblockOffset
	superblock := image[superblockStart : superblockStart+4096]
	binary.LittleEndian.PutUint32(superblock[36:40], declaredDevices)
	binary.LittleEndian.PutUint32(superblock[156:160], uint32(events))
	binary.LittleEndian.PutUint32(superblock[160:164], uint32(events>>32))
	binary.LittleEndian.PutUint32(superblock[992*4:992*4+4], memberNumber)
	binary.LittleEndian.PutUint32(superblock[992*4+12:992*4+16], role)
	binary.LittleEndian.PutUint32(superblock[992*4+16:992*4+20], memberState)
	binary.LittleEndian.PutUint32(superblock[152:156], 0)
	var sum uint64
	for offset := 0; offset+4 <= len(superblock); offset += 4 {
		if offset != 152 {
			sum += uint64(binary.LittleEndian.Uint32(superblock[offset : offset+4]))
		}
	}
	binary.LittleEndian.PutUint32(superblock[152:156], uint32(sum)+uint32(sum>>32))
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
	binary.LittleEndian.PutUint64(superblock[80:88], 32)
	binary.LittleEndian.PutUint32(superblock[92:96], 2)
	binary.LittleEndian.PutUint64(superblock[128:136], 16)
	binary.LittleEndian.PutUint64(superblock[136:144], 32)
	binary.LittleEndian.PutUint64(superblock[144:152], 8)
	copy(superblock[168:184], []byte("FIRST-MEMBER-ID"))
	binary.LittleEndian.PutUint64(superblock[200:208], 5)
	binary.LittleEndian.PutUint32(superblock[220:224], 2)
	binary.LittleEndian.PutUint16(superblock[256:258], 0)
	binary.LittleEndian.PutUint16(superblock[258:260], 1)
	sealMDV12SuperblockForCommand(superblock)
}

func syntheticGPTImageForMDV12Member(memberNumber uint32, role uint16, events uint64) []byte {
	image := syntheticGPTImageForCommand()
	const superblockOffset = 3*512 + 4096
	superblock := image[superblockOffset : superblockOffset+260]
	binary.LittleEndian.PutUint32(superblock[160:164], memberNumber)
	binary.LittleEndian.PutUint16(superblock[256+memberNumber*2:258+memberNumber*2], role)
	if memberNumber == 1 {
		copy(superblock[168:184], []byte("SECOND-MEMBER-ID"))
	}
	binary.LittleEndian.PutUint64(superblock[200:208], events)
	sealMDV12SuperblockForCommand(superblock)
	return image
}

func sealMDV12SuperblockForCommand(superblock []byte) {
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
