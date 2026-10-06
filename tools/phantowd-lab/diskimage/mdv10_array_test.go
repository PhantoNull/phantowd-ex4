// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import "testing"

func TestCompareMDV10ImageSetRequiresCompleteConsistentArrayRoles(t *testing.T) {
	first := mdv10ArrayComponent(1, 1, 0, 0, 42)
	second := mdv10ArrayComponent(2, 1, 1, 1, 42)
	report, err := CompareMDV10ImageSet([]MDV10ImageComponent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if report.CandidateComponents != 2 || len(report.Arrays) != 1 {
		t.Fatalf("expected two components grouped into one array: %+v", report)
	}
	array := report.Arrays[0]
	if array.Status != MDV10ArrayMetadataConsistent || array.RAIDDisks != 2 ||
		array.ObservedActiveRoles != 2 || len(array.MissingActiveRoles) != 0 ||
		len(array.Members) != 2 || array.ArrayIdentityFingerprint == "" ||
		array.WDCompatibility != "unqualified" || report.AssemblyPerformed || report.MountPerformed {
		t.Fatalf("unexpected generic MD 1.0 comparison: %+v", array)
	}
}

func TestCompareMDV10ImageSetRequiresReviewForMissingConflictingOrUncertainMetadata(t *testing.T) {
	tests := []struct {
		name            string
		firstFeatureMap uint32
		second          *MDV10ImageComponent
		status          MDV10ArrayStatus
	}{
		{name: "missing active role", status: MDV10ArrayIncomplete},
		{
			name: "duplicate active role", status: MDV10ArrayAmbiguous,
			second: mdv10ArrayComponentPointer(2, 1, 1, 0, 42),
		},
		{
			name: "divergent events", status: MDV10ArrayDivergent,
			second: mdv10ArrayComponentPointer(2, 1, 1, 1, 43),
		},
		{
			name: "conflicting geometry", status: MDV10ArrayConflicting,
			second: mdv10ArrayComponentPointer(2, 1, 1, 1, 42, func(report *MDV10Report) {
				report.ArraySizeSectors++
			}),
		},
		{
			name: "unknown feature map", status: MDV10ArrayIncomplete,
			firstFeatureMap: 1,
			second: mdv10ArrayComponentPointer(2, 1, 1, 1, 42, func(report *MDV10Report) {
				report.FeatureMap = 1
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			first := mdv10ArrayComponent(1, 1, 0, 0, 42, func(report *MDV10Report) {
				report.FeatureMap = test.firstFeatureMap
			})
			components := []MDV10ImageComponent{first}
			if test.second != nil {
				components = append(components, *test.second)
			}
			report, err := CompareMDV10ImageSet(components)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Arrays) != 1 || report.Arrays[0].Status != test.status {
				t.Fatalf("expected array status %q, got %+v", test.status, report)
			}
		})
	}
}

func mdv10ArrayComponent(inputIndex, partitionNumber int, memberNumber uint32, role uint16, events uint64, tweaks ...func(*MDV10Report)) MDV10ImageComponent {
	component := MDV10ImageComponent{
		InputIndex: inputIndex, PartitionNumber: partitionNumber,
		Report: MDV10Report{
			SchemaVersion: 1, Status: MDV10StatusCandidate, MetadataVersion: "1.0", SuperblockChecksumStatus: "valid",
			ArrayIdentityFingerprint: "array-fingerprint", MemberIdentityFingerprint: string(rune('a' + memberNumber)),
			ArrayLevel: 1, ArrayLayout: 0, ArraySizeSectors: 4096, ChunkSizeSectors: 0,
			RAIDDisks: 2, MaxDevices: 3, MemberNumber: memberNumber, MemberRole: role,
			MemberRoleDescription: "active-slot", FeatureMap: 0, Events: events,
			RawIdentityRedacted: true, WDCompatibility: "unqualified",
		},
	}
	for _, tweak := range tweaks {
		tweak(&component.Report)
	}
	return component
}

func mdv10ArrayComponentPointer(inputIndex, partitionNumber int, memberNumber uint32, role uint16, events uint64, tweaks ...func(*MDV10Report)) *MDV10ImageComponent {
	component := mdv10ArrayComponent(inputIndex, partitionNumber, memberNumber, role, events, tweaks...)
	return &component
}
