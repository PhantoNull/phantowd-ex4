// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package storageinventory

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestAssessProducesNonExecutablePreviewForSyntheticCandidate(t *testing.T) {
	report, err := Assess(bytes.NewBufferString(assessmentFixture("not_collected", singleDiskFixture(1, "/dev/sda"))))
	if err != nil {
		t.Fatal(err)
	}
	if report.Classification != ClassificationCandidate || report.CompatibilityQualified || report.CanExecute ||
		report.MutationsPerformed || report.AssemblyPerformed || report.MountPerformed || !report.IdentityMaterialRedacted {
		t.Fatalf("candidate must remain explicitly unqualified and non-executable: %+v", report)
	}
	if len(report.Volumes) != 1 || report.Volumes[0].LogicalVolumeNumber != 1 ||
		report.Plan.Mode != "dry-run" || report.Plan.Executable || len(report.Plan.Operations) != 0 {
		t.Fatalf("expected one redacted dry-run preview without operations: %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"fixture-serial-001", "fixture-wwn-001", "fixture-partuuid-001", "fixture-fs-uuid-001", "fixture-md-uuid-001", "/dev/sda"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("assessment leaked source identity %q: %s", secret, encoded)
		}
	}
}

func TestAssessClassifiesLegacyMetadataEvidenceConservatively(t *testing.T) {
	for _, test := range []struct {
		state string
		want  Classification
	}{
		{state: "absent", want: ClassificationDamaged},
		{state: "malformed", want: ClassificationDamaged},
		{state: "present_unqualified", want: ClassificationAmbiguous},
		{state: "not_collected", want: ClassificationCandidate},
	} {
		t.Run(test.state, func(t *testing.T) {
			report, err := Assess(bytes.NewBufferString(assessmentFixture(test.state, singleDiskFixture(1, "/dev/sda"))))
			if err != nil {
				t.Fatal(err)
			}
			if report.Classification != test.want {
				t.Fatalf("classification=%q, want %q: %+v", report.Classification, test.want, report)
			}
			if report.CanExecute || report.CompatibilityQualified || len(report.Plan.Operations) != 0 {
				t.Fatalf("unqualified metadata evidence became actionable: %+v", report)
			}
		})
	}
}

func TestAssessClassifiesIdentityCollisionsAndIncompleteEvidence(t *testing.T) {
	duplicate := strings.Replace(singleDiskFixture(1, "/dev/sda"),
		`"volumes":[{"id":"volume-a","logical_volume_number":1,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","md_uuid":"fixture-md-uuid-001","member_partition_ids":["partition-a"]}]`,
		`"volumes":[{"id":"volume-a","logical_volume_number":1,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","md_uuid":"fixture-md-uuid-001","member_partition_ids":["partition-a"]},{"id":"volume-b","logical_volume_number":2,"filesystem_uuid":"fixture-fs-uuid-001","filesystem_type":"ext4","member_partition_ids":["partition-a"]}]`, 1)
	missingIdentity := strings.Replace(singleDiskFixture(1, "/dev/sda"),
		`"wwn":"fixture-wwn-001","serial":"fixture-serial-001"`,
		`"wwn":"","serial":""`, 1)
	damaged := strings.Replace(singleDiskFixture(1, "/dev/sda"), `"filesystem_uuid":"fixture-fs-uuid-001"`, `"filesystem_uuid":""`, 1)
	unsupportedSchema := strings.Replace(singleDiskFixture(1, "/dev/sda"), `"schema_version":1`, `"schema_version":2`, 1)

	for _, test := range []struct {
		name     string
		manifest string
		want     Classification
	}{
		{name: "conflicting filesystem identities", manifest: duplicate, want: ClassificationAmbiguous},
		{name: "missing disk identity", manifest: missingIdentity, want: ClassificationAmbiguous},
		{name: "missing filesystem identity", manifest: damaged, want: ClassificationAmbiguous},
		{name: "unsupported nested schema takes precedence", manifest: unsupportedSchema, want: ClassificationUnsupported},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := Assess(bytes.NewBufferString(assessmentFixture("not_collected", test.manifest)))
			if err != nil {
				t.Fatal(err)
			}
			if report.Classification != test.want || report.CanExecute || report.CompatibilityQualified ||
				len(report.Volumes) != 0 || len(report.Plan.Operations) != 0 {
				t.Fatalf("unsafe or incorrect classification: %+v", report)
			}
		})
	}
}

func TestAssessRejectsUnsupportedAndMalformedRequestsWithoutEchoingInput(t *testing.T) {
	for _, test := range []struct {
		name  string
		input string
		want  Classification
	}{
		{name: "unknown schema version", input: assessmentFixtureVersion("2", "not_collected", singleDiskFixture(1, "/dev/sda")), want: ClassificationUnsupported},
		{name: "unknown metadata state", input: assessmentFixture("healthy", singleDiskFixture(1, "/dev/sda")), want: ClassificationUnsupported},
		{name: "missing inventory", input: `{"format":"phantowd-storage-assessment","schema_version":1,"legacy_volume_metadata_state":"not_collected"}`, want: ClassificationDamaged},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := Assess(strings.NewReader(test.input))
			if err != nil {
				t.Fatal(err)
			}
			if report.Classification != test.want || report.CanExecute || report.CompatibilityQualified {
				t.Fatalf("unexpected request classification: %+v", report)
			}
			encoded, _ := json.Marshal(report)
			if bytes.Contains(encoded, []byte("fixture-")) {
				t.Fatalf("assessment leaked fixture identities: %s", encoded)
			}
		})
	}
	if _, err := Assess(strings.NewReader("{")); err == nil {
		t.Fatal("malformed JSON accepted")
	}
	if _, err := Assess(bytes.NewReader(bytes.Repeat([]byte{' '}, maxInputBytes+1))); err == nil {
		t.Fatal("oversized assessment accepted")
	}
}

func TestAssessRejectsUnknownFieldsAndDuplicateKeys(t *testing.T) {
	valid := assessmentFixture("not_collected", singleDiskFixture(1, "/dev/sda"))
	unknownField := strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"future_field":true`, 1)
	duplicateField := strings.Replace(valid, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1)
	for _, test := range []struct {
		name  string
		input string
		want  Classification
	}{
		{name: "unknown field", input: unknownField, want: ClassificationUnsupported},
		{name: "duplicate key", input: duplicateField, want: ClassificationAmbiguous},
	} {
		t.Run(test.name, func(t *testing.T) {
			report, err := Assess(strings.NewReader(test.input))
			if err != nil {
				t.Fatal(err)
			}
			if report.Classification != test.want || report.CanExecute || report.CompatibilityQualified || len(report.Plan.Operations) != 0 {
				t.Fatalf("unexpected malformed-envelope classification: %+v", report)
			}
		})
	}
	if _, err := Assess(strings.NewReader(valid + ` {}`)); err == nil {
		t.Fatal("trailing JSON value accepted")
	}
}

func assessmentFixture(metadataState, inventory string) string {
	return assessmentFixtureVersion("1", metadataState, inventory)
}

func assessmentFixtureVersion(version, metadataState, inventory string) string {
	return `{"format":"phantowd-storage-assessment","schema_version":` + version +
		`,"legacy_volume_metadata_state":"` + metadataState + `","inventory":` + inventory + `}`
}
