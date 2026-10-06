// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package storageinventory

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestInspectIdentitySurvivesBayAndDeviceReordering(t *testing.T) {
	first, err := Inspect(bytes.NewReader([]byte(singleDiskFixture(1, "/dev/sda"))))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Inspect(bytes.NewReader([]byte(singleDiskFixture(4, "/dev/sdd"))))
	if err != nil {
		t.Fatal(err)
	}
	if !first.Valid || !second.Valid {
		t.Fatalf("synthetic inventories should validate: first=%+v second=%+v", first, second)
	}
	if len(first.Volumes) != 1 || len(second.Volumes) != 1 {
		t.Fatalf("expected one volume in each report: first=%+v second=%+v", first, second)
	}
	if first.Volumes[0].IdentityFingerprint != second.Volumes[0].IdentityFingerprint {
		t.Fatalf("bay/device reordering changed stable identity: %q != %q", first.Volumes[0].IdentityFingerprint, second.Volumes[0].IdentityFingerprint)
	}
	if first.Volumes[0].HistoricalDataMount != "/mnt/HD/HD_a2" || second.Volumes[0].HistoricalDataMount != "/mnt/HD/HD_a2" {
		t.Fatalf("historical path should derive from logical number, not bay: first=%+v second=%+v", first.Volumes[0], second.Volumes[0])
	}
	encoded, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-serial-001", "fixture-wwn-001", "fixture-partuuid-001", "fixture-fs-uuid-001", "fixture-md-uuid-001"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("identity material %q leaked in report: %s", secret, encoded)
		}
	}
}

func TestInspectAllowsFilesystemOnlyIdentity(t *testing.T) {
	fixture := strings.Replace(singleDiskFixture(1, "/dev/sda"), `,"md_uuid":"fixture-md-uuid-001"`, "", 1)
	report, err := Inspect(bytes.NewReader([]byte(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if !report.Valid || len(report.Volumes) != 1 || report.Volumes[0].IdentityBasis != "filesystem" {
		t.Fatalf("filesystem-only volume should validate: %+v", report)
	}
}

func TestInspectRejectsDuplicateFilesystemIdentityWithoutEchoingIt(t *testing.T) {
	fixture := strings.Replace(singleDiskFixture(1, "/dev/sda"),
		`"volumes":[{"id":"volume-a","logical_volume_number":1,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","md_uuid":"fixture-md-uuid-001","member_partition_ids":["partition-a"]}]`,
		`"volumes":[{"id":"volume-a","logical_volume_number":1,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","md_uuid":"fixture-md-uuid-001","member_partition_ids":["partition-a"]},{"id":"volume-b","logical_volume_number":2,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","member_partition_ids":["partition-a"]}]`,
		1)
	report, err := Inspect(bytes.NewReader([]byte(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid || len(report.Violations) == 0 {
		t.Fatalf("duplicate filesystem identities must fail closed: %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "fixture-fs-uuid-001") || strings.Contains(string(encoded), "fixture-serial-001") {
		t.Fatalf("invalid report leaked raw identity material: %s", encoded)
	}
}

func TestInspectRejectsUnresolvedPartitionReference(t *testing.T) {
	fixture := strings.Replace(singleDiskFixture(1, "/dev/sda"), `"partition-a"]`, `"missing-partition"]`, 1)
	report, err := Inspect(bytes.NewReader([]byte(fixture)))
	if err != nil {
		t.Fatal(err)
	}
	if report.Valid || len(report.Violations) == 0 {
		t.Fatalf("unknown member partition must fail closed: %+v", report)
	}
}

func TestInspectRejectsDuplicateJSONKeysAndUnknownFields(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
	}{
		{name: "duplicate key", input: `{"format":"phantowd-storage-inventory","format":"phantowd-storage-inventory","schema_version":1,"disks":[],"partitions":[],"volumes":[]}`},
		{name: "unknown key", input: `{"format":"phantowd-storage-inventory","schema_version":1,"disks":[],"partitions":[],"volumes":[],"vendor_xml":{}}`},
		{name: "case-mismatched key", input: `{"Format":"phantowd-storage-inventory","schema_version":1,"disks":[],"partitions":[],"volumes":[]}`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := Inspect(bytes.NewReader([]byte(test.input))); err == nil {
				t.Fatal("ambiguous or unknown schema input was accepted")
			}
		})
	}
}

func FuzzStorageInventoryAndDryRunNeverBecomeExecutable(f *testing.F) {
	f.Add([]byte(singleDiskFixture(1, "/dev/sda")))
	f.Add([]byte(`{"format":"phantowd-storage-inventory","schema_version":1,"disks":[],"partitions":[],"volumes":[]}`))
	f.Add([]byte(`{"format":"phantowd-storage-inventory","format":"phantowd-storage-inventory"}`))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		report, err := Inspect(bytes.NewReader(data))
		if !report.IdentityMaterialRedacted || report.Format != format || report.SchemaVersion != schemaVersion {
			t.Fatalf("inventory parser lost its fixed redaction/schema guarantees: %+v", report)
		}
		if err == nil {
			if report.Valid {
				if len(report.Violations) != 0 || len(report.Volumes) != report.VolumeCount {
					t.Fatalf("valid inventory report violates count/status invariants: %+v", report)
				}
			} else if len(report.Violations) == 0 || len(report.Volumes) != 0 {
				t.Fatalf("invalid inventory did not fail closed: %+v", report)
			}
		}

		assessmentInput := `{"format":"phantowd-storage-assessment","schema_version":1,"legacy_volume_metadata_state":"not_collected","inventory":` + string(data) + `}`
		assessment, _ := Assess(strings.NewReader(assessmentInput))
		if !assessment.IdentityMaterialRedacted || assessment.CanExecute || assessment.Plan.Executable ||
			assessment.MutationsPerformed || assessment.AssemblyPerformed || assessment.MountPerformed ||
			len(assessment.Plan.Operations) != 0 {
			t.Fatalf("untrusted inventory input became executable or lost redaction: %+v", assessment)
		}
	})
}

func singleDiskFixture(bay int, device string) string {
	return fmt.Sprintf(`{
  "format":"phantowd-storage-inventory",
  "schema_version":1,
  "disks":[{"id":"disk-a","wwn":"fixture-wwn-001","serial":"fixture-serial-001","bay":%d,"device":"%s"}],
  "partitions":[{"id":"partition-a","disk_id":"disk-a","number":2,"partuuid":"fixture-partuuid-001"}],
  "volumes":[{"id":"volume-a","logical_volume_number":1,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","md_uuid":"fixture-md-uuid-001","member_partition_ids":["partition-a"]}]
}`, bay, device)
}
