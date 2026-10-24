// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"slices"
	"testing"
)

func TestExtEncryptionDeclarationRequiresReviewWithoutReadingFiles(t *testing.T) {
	image := syntheticGPTImage()
	putExtSuperblock(image, 40, extFixture{blockCount: 5, revision: 1, state: extStateClean,
		featureIncompat: 0x10000, featureROCompat: extROCompatMetadataChecksum})
	before := append([]byte(nil), image...)
	report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
	if err != nil || report.Status != ExtStatusCandidate {
		t.Fatalf("report=%+v err=%v", report, err)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(encoded, &object); err != nil {
		t.Fatal(err)
	}
	value, exists := object["feature_review"]
	if !exists {
		t.Fatal("encryption declaration has no explicit feature review")
	}
	var review struct {
		Required bool     `json:"required"`
		Declared []string `json:"declared"`
	}
	if err := json.Unmarshal(value, &review); err != nil {
		t.Fatal(err)
	}
	if !review.Required || !bytes.Contains(value, []byte(`"incompat-encrypt"`)) || report.FeatureIncompat != 0x10000 {
		t.Fatalf("encryption declaration silently omitted: %s", value)
	}
	if !bytes.Equal(before, image) || report.BlockDeviceOpened || report.MutationsPerformed || report.MountPerformed {
		t.Fatal("feature observation changed source or acquired device authority")
	}
}

func TestExtFeatureReviewPreservesDeclarationsAndUnclassifiedBits(t *testing.T) {
	for _, test := range []struct {
		name                 string
		compat, incompat, ro uint32
		declaration          string
		required             bool
		unknown              [3]uint32
	}{
		{name: "ordinary ext declarations", compat: 0x3c, incompat: 0x2c2, ro: 0x46b, declaration: "incompat-flex-bg"},
		{name: "fast commit", compat: 0x400, declaration: "compat-fast-commit", required: true},
		{name: "journal device", incompat: 8, declaration: "incompat-journal-dev", required: true},
		{name: "compression", incompat: 1, declaration: "incompat-compression", required: true},
		{name: "multiple mount protection", incompat: 0x100, declaration: "incompat-mmp", required: true},
		{name: "inline data", incompat: 0x8000, declaration: "incompat-inline-data", required: true},
		{name: "casefold", incompat: 0x20000, declaration: "incompat-casefold", required: true},
		{name: "quotas", ro: 0x100, declaration: "ro-compat-quota", required: true},
		{name: "bigalloc", ro: 0x200, declaration: "ro-compat-bigalloc", required: true},
		{name: "read-only image", ro: 0x1000, declaration: "ro-compat-readonly", required: true},
		{name: "project quota", ro: 0x2000, declaration: "ro-compat-project", required: true},
		{name: "verity", ro: 0x8000, declaration: "ro-compat-verity", required: true},
		{name: "unclassified compat", compat: 0x80000000, required: true, unknown: [3]uint32{0x80000000, 0, 0}},
		{name: "unclassified incompat", incompat: 0x80000000, required: true, unknown: [3]uint32{0, 0x80000000, 0}},
		{name: "unclassified ro", ro: 0x80000000, required: true, unknown: [3]uint32{0, 0, 0x80000000}},
	} {
		t.Run(test.name, func(t *testing.T) {
			metadata := make([]byte, extSuperblockBytes)
			putExtSuperblockFields(metadata, extFixture{blockCount: 5, revision: 1, state: extStateClean,
				featureIncompat: test.incompat, featureROCompat: test.ro})
			// Compat is independent of the fixture helper's default has_journal bit.
			binary.LittleEndian.PutUint32(metadata[0x5c:0x60], test.compat)
			refreshExtSuperblockChecksum(metadata)
			reader := fixedMetadataReader{offset: 40*logicalSectorBytes + extSuperblockOffset, data: metadata}
			report, err := InspectExtSuperblock(reader, 128*logicalSectorBytes, 40, 49)
			if err != nil || report.Status != ExtStatusCandidate || report.FeatureReview == nil {
				t.Fatalf("report=%+v err=%v", report, err)
			}
			review := report.FeatureReview
			if review.Required != test.required || [3]uint32{review.UnclassifiedCompat, review.UnclassifiedIncompat, review.UnclassifiedROCompat} != test.unknown {
				t.Fatalf("feature declarations silently lost: %+v", review)
			}
			if test.declaration != "" && !slices.Contains(review.Declared, test.declaration) {
				t.Fatalf("missing %q: %+v", test.declaration, review)
			}
			if review.Declared == nil || report.SpaceCounters.MigrationCapacityQualified {
				t.Fatal("empty declaration or capacity gained authority")
			}
			if review.Reasons == nil || (test.required && test.unknown == [3]uint32{} && len(review.Reasons) == 0) {
				t.Fatal("required feature review lost its fixed reason")
			}
		})
	}
}

func TestExtFeatureReviewUnknownIsNotAnEmptySuccessfulObservation(t *testing.T) {
	for _, test := range []struct {
		name     string
		change   func([]byte)
		observed bool
	}{
		{name: "bad checksum", change: func(sb []byte) { sb[0x200] ^= 1 }},
		{name: "unsupported revision", change: func(sb []byte) { binary.LittleEndian.PutUint32(sb[0x4c:0x50], 2) }},
		{name: "no ext magic", change: func(sb []byte) { sb[0x38] = 0 }},
		{name: "legacy revision ignores dynamic feature bytes", observed: true, change: func(sb []byte) {
			binary.LittleEndian.PutUint32(sb[0x4c:0x50], 0)
			sb[0xd0], sb[0xe4] = 1, 1
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			image := syntheticGPTImage()
			putExtSuperblock(image, 40, extFixture{blockCount: 5, revision: 1, featureIncompat: 0x10000, featureROCompat: extROCompatMetadataChecksum})
			test.change(image[40*logicalSectorBytes+extSuperblockOffset : 40*logicalSectorBytes+extSuperblockOffset+extSuperblockBytes])
			report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
			if err != nil || report.SchemaVersion != 4 || (report.FeatureReview != nil) != test.observed {
				t.Fatalf("observation contract: %+v %v", report, err)
			}
			if test.observed && (report.FeatureReview.Required || len(report.FeatureReview.Declared) != 0) {
				t.Fatal("legacy feature bytes interpreted as dynamic metadata")
			}
		})
	}
}

func TestExtExternalJournalReferencesRequireSeparateReview(t *testing.T) {
	for _, offset := range []int{0xd0, 0xe4} {
		image := syntheticGPTImage()
		putExtSuperblock(image, 40, extFixture{blockCount: 5, revision: 1, state: extStateClean, featureROCompat: extROCompatMetadataChecksum})
		sb := image[40*logicalSectorBytes+extSuperblockOffset : 40*logicalSectorBytes+extSuperblockOffset+extSuperblockBytes]
		sb[offset] = 1
		refreshExtSuperblockChecksum(sb)
		report, err := InspectExtSuperblock(bytes.NewReader(image), int64(len(image)), 40, 49)
		if err != nil || report.Status != ExtStatusCandidate || report.FeatureReview == nil || !report.FeatureReview.Required {
			t.Fatalf("external journal reference silently omitted at%x: %+v %v", offset, report.FeatureReview, err)
		}
		encoded, err := json.Marshal(report.FeatureReview)
		if err != nil || !bytes.Contains(encoded, []byte(`"external_journal_reference":true`)) {
			t.Fatalf("missing redacted reference observation: %s %v", encoded, err)
		}
	}
}
