// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package diskimage

import "testing"

func TestCompareMDV12ImageSetRequiresConsistentCompleteActiveRoles(t *testing.T) {
	first := arrayComponent(1, 1, 0, 0, 41)
	second := arrayComponent(2, 1, 1, 1, 41)

	report, err := CompareMDV12ImageSet([]MDV12ImageComponent{first, second})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 1 {
		t.Fatalf("got %d array groups, want one: %+v", len(report.Arrays), report)
	}
	array := report.Arrays[0]
	if array.Status != MDV12ArrayMetadataConsistent || array.RAIDDisks != 2 ||
		array.ObservedActiveRoles != 2 || len(array.MissingActiveRoles) != 0 ||
		len(array.Members) != 2 || array.ArrayIdentityFingerprint == "" ||
		array.WDCompatibility != "unqualified" || report.AssemblyPerformed || report.MountPerformed {
		t.Fatalf("unexpected metadata comparison: %+v", array)
	}
}

func TestCompareMDV12ImageSetFailsClosedForIncompleteOrConflictingMembers(t *testing.T) {
	tests := []struct {
		name   string
		input  []MDV12ImageComponent
		status MDV12ArrayStatus
	}{
		{
			name:   "missing active member",
			input:  []MDV12ImageComponent{arrayComponent(1, 1, 0, 0, 41)},
			status: MDV12ArrayIncomplete,
		},
		{
			name: "duplicate active role",
			input: []MDV12ImageComponent{
				arrayComponent(1, 1, 0, 0, 41),
				arrayComponent(2, 1, 1, 0, 41),
			},
			status: MDV12ArrayAmbiguous,
		},
		{
			name: "duplicate member identity",
			input: []MDV12ImageComponent{
				arrayComponent(1, 1, 0, 0, 41),
				arrayComponent(2, 1, 1, 1, 41, func(report *MDV12Report) {
					report.MemberIdentityFingerprint = "member-fingerprint-a"
				}),
			},
			status: MDV12ArrayAmbiguous,
		},
		{
			name: "event counter mismatch",
			input: []MDV12ImageComponent{
				arrayComponent(1, 1, 0, 0, 41),
				arrayComponent(2, 1, 1, 1, 42),
			},
			status: MDV12ArrayDivergent,
		},
		{
			name: "layout mismatch",
			input: []MDV12ImageComponent{
				arrayComponent(1, 1, 0, 0, 41),
				arrayComponent(2, 1, 1, 1, 41, func(report *MDV12Report) { report.ArrayLayout = 7 }),
			},
			status: MDV12ArrayConflicting,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			report, err := CompareMDV12ImageSet(test.input)
			if err != nil {
				t.Fatal(err)
			}
			if len(report.Arrays) != 1 || report.Arrays[0].Status != test.status {
				t.Fatalf("status=%v, want %v; report=%+v", report.Arrays, test.status, report)
			}
		})
	}
}

func TestCompareMDV12ImageSetDoesNotTrustMissingArrayIdentity(t *testing.T) {
	component := arrayComponent(1, 1, 0, 0, 41)
	component.Report.ArrayIdentityFingerprint = ""
	report, err := CompareMDV12ImageSet([]MDV12ImageComponent{component})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Arrays) != 0 || report.UnidentifiedCandidateComponents != 1 {
		t.Fatalf("unidentified component was grouped: %+v", report)
	}
}

func TestCompareMDV12ImageSetRejectsDuplicateLocationsAndInvalidIndexes(t *testing.T) {
	base := arrayComponent(1, 1, 0, 0, 41)
	for _, input := range [][]MDV12ImageComponent{
		{base, base},
		{{InputIndex: 0, PartitionNumber: 1, Report: base.Report}},
		{{InputIndex: 1, PartitionNumber: 0, Report: base.Report}},
	} {
		if _, err := CompareMDV12ImageSet(input); err == nil {
			t.Fatalf("accepted invalid component locations: %+v", input)
		}
	}
}

func arrayComponent(inputIndex, partitionNumber int, memberNumber uint32, role uint16, events uint64, tweaks ...func(*MDV12Report)) MDV12ImageComponent {
	report := MDV12Report{
		Status:                    MDStatusCandidate,
		MetadataVersion:           "1.2",
		ArrayIdentityFingerprint:  "array-fingerprint",
		MemberIdentityFingerprint: "member-fingerprint-" + string(rune('a'+memberNumber)),
		ArrayLevel:                1,
		ArrayLayout:               0,
		ArraySizeSectors:          1024,
		ChunkSizeSectors:          0,
		RAIDDisks:                 2,
		MaxDevices:                2,
		FeatureMap:                0,
		Events:                    events,
		MemberNumber:              memberNumber,
		MemberRole:                role,
		MemberRoleDescription:     "active-slot",
		SuperblockChecksumStatus:  "valid",
		RawIdentityRedacted:       true,
		WDCompatibility:           "unqualified",
		BlockDeviceOpened:         false,
		MutationsPerformed:        false,
		AssemblyPerformed:         false,
		MountPerformed:            false,
	}
	for _, tweak := range tweaks {
		tweak(&report)
	}
	return MDV12ImageComponent{InputIndex: inputIndex, PartitionNumber: partitionNumber, Report: report}
}
