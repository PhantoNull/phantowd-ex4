// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mdmetadata

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestCompareComponentsRecognizesCompleteActiveRoles(t *testing.T) {
	first := testMDV10Observation(t, 0)
	second := testMDV10Observation(t, 1)

	comparison, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: first},
		{DiskIndex: 2, PartitionNumber: 1, Observation: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if comparison.CandidateComponents != 2 || comparison.UnqualifiedComponents != 0 ||
		comparison.UnidentifiedCandidateComponents != 0 || len(comparison.Arrays) != 1 {
		t.Fatalf("unexpected component-set summary: %+v", comparison)
	}
	array := comparison.Arrays[0]
	if array.Status != ArrayMetadataConsistent || array.MemberCount != 2 ||
		array.ObservedActiveRoles != 2 || len(array.MissingActiveRoles) != 0 {
		t.Fatalf("complete RAID1 roles not recognized: %+v", array)
	}
}

func TestCompareComponentsRequiresEveryActiveRole(t *testing.T) {
	component := testMDV10Observation(t, 0)
	comparison, err := CompareComponents([]ComponentEvidence{{
		DiskIndex: 1, PartitionNumber: 1, Observation: component,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Arrays) != 1 || comparison.Arrays[0].Status != ArrayIncomplete ||
		comparison.Arrays[0].ObservedActiveRoles != 1 || len(comparison.Arrays[0].MissingActiveRoles) != 1 ||
		comparison.Arrays[0].MissingActiveRoles[0] != 1 {
		t.Fatalf("missing active RAID role was not made explicit: %+v", comparison)
	}
}

func TestCompareComponentsMarksUnequalEventCountersDivergent(t *testing.T) {
	first, second := testMDV10Observation(t, 0), testMDV10Observation(t, 1)
	second.Events++
	comparison, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: first},
		{DiskIndex: 2, PartitionNumber: 1, Observation: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Arrays) != 1 || comparison.Arrays[0].Status != ArrayDivergentEvents ||
		comparison.Arrays[0].ObservedActiveRoles != 2 {
		t.Fatalf("divergent component events were not classified: %+v", comparison)
	}
}

func TestCompareComponentsMarksDisagreeingArrayFieldsConflicting(t *testing.T) {
	first, second := testMDV10Observation(t, 0), testMDV10Observation(t, 1)
	second.ArraySizeSectors++
	comparison, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: first},
		{DiskIndex: 2, PartitionNumber: 1, Observation: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Arrays) != 1 || comparison.Arrays[0].Status != ArrayConflicting {
		t.Fatalf("conflicting array-level metadata was not refused: %+v", comparison)
	}
}

func TestCompareComponentsMarksDifferentComponentDataSizesConflicting(t *testing.T) {
	first, second := testMDV10Observation(t, 0), testMDV10Observation(t, 1)
	second.ComponentDataSectors++
	comparison, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: first},
		{DiskIndex: 2, PartitionNumber: 1, Observation: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Arrays) != 1 || comparison.Arrays[0].Status != ArrayConflicting {
		t.Fatalf("different component data sizes were not classified as conflicting: %+v", comparison)
	}
}

func TestCompareComponentsMarksDuplicateActiveRoleAmbiguous(t *testing.T) {
	first, second := testMDV10Observation(t, 0), testMDV10Observation(t, 1)
	second.MemberRole = 0
	comparison, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: first},
		{DiskIndex: 2, PartitionNumber: 1, Observation: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Arrays) != 1 || comparison.Arrays[0].Status != ArrayAmbiguous {
		t.Fatalf("duplicate active RAID role was not made ambiguous: %+v", comparison)
	}
}

func TestCompareComponentsDoesNotPromoteDamagedMetadata(t *testing.T) {
	component := testMDV10Observation(t, 0)
	component.Status = StatusDamaged
	comparison, err := CompareComponents([]ComponentEvidence{{
		DiskIndex: 1, PartitionNumber: 1, Observation: component,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if comparison.CandidateComponents != 0 || comparison.UnqualifiedComponents != 1 || len(comparison.Arrays) != 0 {
		t.Fatalf("damaged metadata was promoted into an array: %+v", comparison)
	}
}

func TestCompareComponentsRejectsRepeatedTransientLocation(t *testing.T) {
	component := testMDV10Observation(t, 0)
	_, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: component},
		{DiskIndex: 1, PartitionNumber: 1, Observation: component},
	})
	if !errors.Is(err, ErrInvalidComponentSet) {
		t.Fatalf("duplicate disk/partition evidence was not rejected: %v", err)
	}
}

func TestCompareComponentsDoesNotGroupCandidateWithoutArrayIdentity(t *testing.T) {
	component := testMDV10Observation(t, 0)
	component.ArrayIdentityFingerprint = ""
	comparison, err := CompareComponents([]ComponentEvidence{{
		DiskIndex: 1, PartitionNumber: 1, Observation: component,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if comparison.CandidateComponents != 1 || comparison.UnidentifiedCandidateComponents != 1 || len(comparison.Arrays) != 0 {
		t.Fatalf("unidentified component was grouped into an array: %+v", comparison)
	}
}

func TestCompareComponentsKeepsDifferentArrayIdentitiesSeparate(t *testing.T) {
	first, second := testMDV10Observation(t, 0), testMDV10Observation(t, 1)
	second.ArrayIdentityFingerprint = strings.Repeat("a", arrayFingerprintByteCount*2)
	comparison, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: first},
		{DiskIndex: 2, PartitionNumber: 1, Observation: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(comparison.Arrays) != 2 || comparison.Arrays[0].Status != ArrayIncomplete ||
		comparison.Arrays[1].Status != ArrayIncomplete {
		t.Fatalf("different array identities were combined: %+v", comparison)
	}
}

func TestCompareComponentsRequiresComponentIdentityForArrayMatching(t *testing.T) {
	component := testMDV10Observation(t, 0)
	component.MemberIdentityFingerprint = ""
	comparison, err := CompareComponents([]ComponentEvidence{{
		DiskIndex: 1, PartitionNumber: 1, Observation: component,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if comparison.CandidateComponents != 0 || comparison.UnqualifiedComponents != 1 || len(comparison.Arrays) != 0 {
		t.Fatalf("component without a unique member identity was promoted: %+v", comparison)
	}
}

func TestCompareComponentsRequiresParserPartitionToMatchBoundLocation(t *testing.T) {
	component := testMDV10Observation(t, 0)
	comparison, err := CompareComponents([]ComponentEvidence{{
		DiskIndex: 1, PartitionNumber: 2, Observation: component,
	}})
	if err != nil {
		t.Fatal(err)
	}
	if comparison.CandidateComponents != 0 || comparison.UnqualifiedComponents != 1 || len(comparison.Arrays) != 0 {
		t.Fatalf("parser evidence was rebound to a different partition: %+v", comparison)
	}
}

func TestCompareComponentsCannotSerializeInternalFingerprints(t *testing.T) {
	first, second := testMDV10Observation(t, 0), testMDV10Observation(t, 1)
	comparison, err := CompareComponents([]ComponentEvidence{
		{DiskIndex: 1, PartitionNumber: 1, Observation: first},
		{DiskIndex: 2, PartitionNumber: 1, Observation: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := json.Marshal(comparison)
	if err != nil || strings.Contains(string(encoded), first.ArrayIdentityFingerprint) ||
		strings.Contains(string(encoded), first.MemberIdentityFingerprint) {
		t.Fatalf("private metadata identity fingerprint was serializable: %s %v", encoded, err)
	}
}

func testMDV10Observation(t *testing.T, member uint32) Observation {
	t.Helper()
	image := syntheticV10Image(member)
	result, err := InspectPartition(bytes.NewReader(image), int64(len(image)),
		Partition{Number: 1, StartLBA: 16, SizeLBA: 80})
	if err != nil {
		t.Fatal(err)
	}
	return result
}
