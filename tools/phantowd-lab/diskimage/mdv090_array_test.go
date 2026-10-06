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
	first := md090ArrayComponentWithNRDisksAndState(1, 1, 0, 0, 42, 2, 1<<1|1<<2)
	second := md090ArrayComponentWithNRDisksAndState(2, 1, 1, 1, 42, 2, 1<<1)

	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 {
		t.Fatalf("got %d array groups, want one: %+v", len(report.Arrays), report)
	}
	array := report.Arrays[0]
	if report.SchemaVersion != 4 || report.CandidateComponents != 2 || array.Status != MDV090ArrayMetadataConsistent ||
		array.RAIDDisks != 2 || len(array.ObservedNRDisks) != 1 || array.ObservedNRDisks[0] != 2 ||
		array.ObservedRAIDRoles != 2 || len(array.MissingRAIDRoles) != 0 ||
		len(array.Members) != 2 || array.ArrayIdentityFingerprint == "" ||
		array.WDCompatibility != "unqualified" || report.AssemblyPerformed || report.MountPerformed {
		t.Fatalf("unexpected generic MD 0.90 comparison: %+v", report)
	}
	if array.DescriptorTableStatus != "consistent" || len(array.DescriptorTableMismatchIndices) != 0 {
		t.Fatalf("matching per-component descriptor projections were not compared: %+v", array)
	}
	if array.Members[0].MemberState != 1<<1|1<<2 ||
		strings.Join(array.Members[0].MemberStateFlags, ",") != "active,sync" ||
		array.Members[1].MemberState != 1<<1 ||
		strings.Join(array.Members[1].MemberStateFlags, ",") != "active" {
		t.Fatalf("per-component stored descriptor flags were lost or treated as array health: %+v", array.Members)
	}
	if len(array.Members[0].DiskDescriptors) != mdV090MaxDevices ||
		!array.Members[0].DiskDescriptors[0].HasNonzeroCoreFields ||
		array.Members[0].DiskDescriptors[0].State != 1<<1|1<<2 ||
		len(array.Members[1].DiskDescriptors) != mdV090MaxDevices ||
		array.Members[1].DiskDescriptors[1].State != 1<<1 {
		t.Fatalf("array-wide descriptor tables were not preserved as per-component snapshots: %+v", array.Members)
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

func TestCompareMDV090ImageSetDetectsStoredDescriptorTableConflict(t *testing.T) {
	first := md090ArrayComponentWithNRDisksAndState(1, 1, 0, 0, 42, 2, 1<<1|1<<2)
	second := md090ArrayComponentWithNRDisksAndState(2, 1, 1, 1, 42, 2, 1<<1)
	second.Report.DiskDescriptors[1].Role = 0

	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayConflicting ||
		report.Arrays[0].DescriptorTableStatus != "mismatched" ||
		len(report.Arrays[0].DescriptorTableMismatchIndices) != 1 ||
		report.Arrays[0].DescriptorTableMismatchIndices[0] != 1 {
		t.Fatalf("stored descriptor disagreement was not surfaced as a metadata conflict: %+v", report)
	}
}

func TestCompareMDV090ImageSetIgnoresRedactedMajorMinorPresence(t *testing.T) {
	first := md090ArrayComponentWithNRDisksAndState(1, 1, 0, 0, 42, 2, 1<<1|1<<2)
	second := md090ArrayComponentWithNRDisksAndState(2, 1, 1, 1, 42, 2, 1<<1)
	second.Report.DiskDescriptors[3].HasNonzeroCoreFields = true

	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayMetadataConsistent ||
		report.Arrays[0].DescriptorTableStatus != "consistent" ||
		len(report.Arrays[0].DescriptorTableMismatchIndices) != 0 {
		t.Fatalf("redacted kernel major/minor presence changed descriptor comparison: %+v", report)
	}
}

func TestCompareMDV090ImageSetReportsVariableNonconstantDeviceCounts(t *testing.T) {
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
		md090ArrayComponentWithNRDisks(2, 1, 1, 1, 42, 3),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayMetadataConsistent ||
		len(report.Arrays[0].ObservedNRDisks) != 2 || report.Arrays[0].ObservedNRDisks[0] != 2 ||
		report.Arrays[0].ObservedNRDisks[1] != 3 {
		t.Fatalf("variable nr_disks field was treated as conflicting or hidden: %+v", report)
	}
}

func TestCompareMDV090ImageSetSpareDoesNotFillAssignedRAIDSlots(t *testing.T) {
	spare := md090ArrayComponentWithNRDisks(3, 1, 2, mdV090RoleSpare, 42, 3)
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
		md090ArrayComponent(2, 1, 1, 1, 42),
		spare,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayMetadataConsistent ||
		report.Arrays[0].ObservedRAIDRoles != 2 || len(report.Arrays[0].MissingRAIDRoles) != 0 {
		t.Fatalf("spare role affected assigned-slot coverage: %+v", report)
	}
}

func TestCompareMDV090ImageSetMarksMissingRAIDRoleIncomplete(t *testing.T) {
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayIncomplete ||
		report.Arrays[0].ObservedRAIDRoles != 1 || len(report.Arrays[0].MissingRAIDRoles) != 1 ||
		report.Arrays[0].MissingRAIDRoles[0] != 1 {
		t.Fatalf("missing assigned RAID slot was not conservatively marked incomplete: %+v", report)
	}
}

func TestCompareMDV090ImageSetRejectsDuplicateAssignedRAIDRole(t *testing.T) {
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
		md090ArrayComponent(2, 1, 1, 0, 42),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayAmbiguous {
		t.Fatalf("duplicate assigned RAID role was not marked ambiguous: %+v", report)
	}
}

func TestCompareMDV090ImageSetRejectsDuplicateMemberNumber(t *testing.T) {
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{
		md090ArrayComponent(1, 1, 0, 0, 42),
		md090ArrayComponent(2, 1, 0, 1, 42),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayAmbiguous {
		t.Fatalf("duplicate member number was not marked ambiguous: %+v", report)
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

func TestCompareMDV090ImageSetRejectsIncompleteDescriptorSnapshot(t *testing.T) {
	component := md090ArrayComponent(1, 1, 0, 0, 42)
	component.Report.DiskDescriptors = component.Report.DiskDescriptors[:mdV090MaxDevices-1]
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{component})
	if err != nil {
		t.Fatal(err)
	}
	if report.CandidateComponents != 0 || report.UnqualifiedComponents != 1 || len(report.Arrays) != 0 {
		t.Fatalf("incomplete descriptor snapshot was treated as a candidate: %+v", report)
	}
}

func TestCompareMDV090ImageSetBoundsCallerSuppliedRAIDCount(t *testing.T) {
	component := md090ArrayComponent(1, 1, 0, 0, 42)
	component.Report.RAIDDisks = ^uint32(0)
	report, err := CompareMDV090ImageSet([]MDV090ImageComponent{component})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 || report.Arrays[0].Status != MDV090ArrayConflicting {
		t.Fatalf("out-of-range caller-supplied RAID count was not rejected safely: %+v", report)
	}
}

func md090ArrayComponent(inputIndex, partitionNumber int, memberNumber, role uint32, events uint64) MDV090ImageComponent {
	return md090ArrayComponentWithNRDisks(inputIndex, partitionNumber, memberNumber, role, events, 2)
}

func md090ArrayComponentWithNRDisks(inputIndex, partitionNumber int, memberNumber, role uint32, events uint64, nrDisks uint32) MDV090ImageComponent {
	return md090ArrayComponentWithNRDisksAndState(inputIndex, partitionNumber, memberNumber, role, events, nrDisks, 0)
}

func md090ArrayComponentWithNRDisksAndState(inputIndex, partitionNumber int, memberNumber, role uint32, events uint64, nrDisks, memberState uint32) MDV090ImageComponent {
	image := syntheticMDV090Component()
	superblock := mdV090Superblock(image)
	binary.LittleEndian.PutUint32(superblock[36:40], nrDisks)
	binary.LittleEndian.PutUint32(superblock[156:160], uint32(events))
	binary.LittleEndian.PutUint32(superblock[160:164], uint32(events>>32))
	binary.LittleEndian.PutUint32(superblock[mdV090ThisDiskOffset:mdV090ThisDiskOffset+4], memberNumber)
	binary.LittleEndian.PutUint32(superblock[mdV090ThisDiskOffset+12:mdV090ThisDiskOffset+16], role)
	binary.LittleEndian.PutUint32(superblock[mdV090ThisDiskOffset+16:mdV090ThisDiskOffset+20], memberState)
	for index := uint32(0); index < 2; index++ {
		descriptor := mdV090DisksOffsetWords*4 + int(index)*mdV090DescriptorBytes
		state := uint32(1 << 1)
		if index == 0 {
			state |= 1 << 2
		}
		binary.LittleEndian.PutUint32(superblock[descriptor:descriptor+4], index)
		binary.LittleEndian.PutUint32(superblock[descriptor+4:descriptor+8], 8)
		binary.LittleEndian.PutUint32(superblock[descriptor+8:descriptor+12], index+1)
		binary.LittleEndian.PutUint32(superblock[descriptor+12:descriptor+16], index)
		binary.LittleEndian.PutUint32(superblock[descriptor+16:descriptor+20], state)
	}
	sealMDV090Superblock(superblock)
	report, err := InspectMDV090Component(bytes.NewReader(image), int64(len(image)))
	if err != nil {
		panic(err)
	}
	return MDV090ImageComponent{InputIndex: inputIndex, PartitionNumber: partitionNumber, Report: report}
}
