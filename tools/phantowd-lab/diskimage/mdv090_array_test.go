// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"strings"
	"testing"
)

func TestCompareMDV090ImageSetReportsCompleteGenericArrayMetadata(t *testing.T) {
	first := md090ArrayComponent(1, 1, 0, 0, 42)
	second := md090ArrayComponent(2, 1, 1, 1, 42)

	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 {
		t.Fatalf("got %d array groups, want one: %+v", len(report.Arrays), report)
	}
	array := report.Arrays[0]
	if report.CandidateComponents != 2 || array.Status != MDV090ArrayMetadataConsistent ||
		array.RAIDDisks != 2 || array.ObservedActiveRoles != 2 || len(array.MissingActiveRoles) != 0 ||
		len(array.Members) != 2 || array.ArrayIdentityFingerprint == "" ||
		array.WDCompatibility != "unqualified" || report.AssemblyPerformed || report.MountPerformed {
		t.Fatalf("unexpected generic MD 0.90 comparison: %+v", report)
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"MD090_PRIVATE_ARRAY_ID", "/dev/sda", "private-disk-path"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("comparison leaked %q: %s", secret, encoded)
		}
	}
}

func TestCompareMDV090ImageSetMarksMissingActiveMemberIncomplete(t *testing.T) {
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayIncomplete ||
		report.Arrays[0].ObservedActiveRoles != 1 || len(report.Arrays[0].MissingActiveRoles) != 1 ||
		report.Arrays[0].MissingActiveRoles[0] != 1 {
		t.Fatalf("single member was not conservatively marked incomplete: %+v", report)
	}
}

func TestCompareMDV090ImageSetRejectsDuplicateActiveRole(t *testing.T) {
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
		md090ArrayComponent(2, 1, 1, 0, 42),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayAmbiguous {
		t.Fatalf("duplicate active role was not marked ambiguous: %+v", report)
	}
}

func TestCompareMDV090ImageSetFlagsDivergentEvents(t *testing.T) {
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
		md090ArrayComponent(2, 1, 1, 1, 41),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayDivergent {
		t.Fatalf("different event counters were not marked divergent: %+v", report)
	}
}

func TestCompareMDV090ImageSetFlagsConflictingArrayGeometry(t *testing.T) {
	first := md090ArrayComponent(1, 1, 0, 0, 42)
	second := md090ArrayComponent(2, 1, 1, 1, 42)
	second.Report.ArrayLevel = 5
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayConflicting {
		t.Fatalf("different array geometry was not marked conflicting: %+v", report)
	}
}

func TestCompareMDV090ImageSetCountsUnidentifiedCandidate(t *testing.T) {
	component := md090ArrayComponent(1, 1, 0, 0, 42)
	component.Report.ArrayIdentityFingerprint = ""
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{component})
	if err != nil {
		t.Fatal(err)
	}
	if report.CandidateComponents != 1 || report.UnidentifiedCandidateComponents != 1 || len(report.Arrays) != 0 {
		t.Fatalf("unidentified component was grouped or omitted: %+v", report)
	}
}

func TestCompareMDV090ImageSetRejectsDuplicateInputLocation(t *testing.T) {
	component := md090ArrayComponent(1, 1, 0, 0, 42)
	_, err := CompareMDV090ImageSet([]MDV090ImageComponent{component, component})
	if err == nil {
		t.Fatal("duplicate image/partition location was accepted")
	}
}

func md090ArrayComponent(inputIndex, partitionNumber int, memberNumber, role uint32, events uint64) MDV090ImageComponent {
	image := syntheticMDV090Component()
	superblock := mdV090Superblock(image)
	binary.LittleEndian.PutUint32(superblock[156:160], uint32(events))
	binary.LittleEndian.PutUint32(superblock[160:164], uint32(events>>32))
	binary.LittleEndian.PutUint32(superblock[mdV090ThisDiskOffset:mdV090ThisDiskOffset+4], memberNumber)
	binary.LittleEndian.PutUint32(superblock[mdV090ThisDiskOffset+12:mdV090ThisDiskOffset+16], role)
	sealMDV090Superblock(superblock)
	report, err := InspectMDV090Component(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		panic(err)
	}
	return MDV090ImageComponent{InputIndex: inputIndex, PartitionNumber: partitionNumber, Report: report}
}
