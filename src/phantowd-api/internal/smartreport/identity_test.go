// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

const identitySerial = "SYNTHETIC-ATA-01"
const identityWWN uint64 = 0x5abcdef123456789

func identityFixture(exit int) string {
	input := strings.Replace(fixture(exit, exit&8 == 0), "PRIVATE-SERIAL", identitySerial, 1)
	return strings.Replace(input, `"wwn":{"id":1234}`, `"wwn":{"naa":5,"oui":11259375,"id":4886718345}`, 1)
}

func TestIdentityComparisonPreservesEveryAssessmentAndExitFlag(t *testing.T) {
	for _, version := range []string{"7,4", "7,5"} {
		for exit := 0; exit < 256; exit++ {
			input := strings.Replace(identityFixture(exit), `"version":[7,4]`, `"version":[`+version+`]`, 1)
			plain, err := Parse([]byte(input), exit)
			if err != nil {
				t.Fatal(err)
			}
			matched, err := ParseMatchingATAIdentity([]byte(input), exit, identitySerial, identityWWN)
			if err != nil || matched != plain {
				t.Fatalf("version=%s exit=%d: matching discarded collection/assessment evidence: %v", version, exit, err)
			}
			if data, err := json.Marshal(matched); err == nil || len(data) != 0 {
				t.Fatal("matched projection became serializable")
			}
		}
	}
}

func TestIdentityComparisonNoFallbackNormalizationOrNumericCoercion(t *testing.T) {
	good := identityFixture(0)
	cases := []struct{ name, from, to string }{
		{"missing-serial", `"serial_number"`, `"other_serial"`},
		{"serial-null", `"serial_number":"` + identitySerial + `"`, `"serial_number":null`},
		{"serial-number", `"serial_number":"` + identitySerial + `"`, `"serial_number":42`},
		{"serial-different", identitySerial, "SYNTHETIC-ATA-02"},
		{"serial-folding", identitySerial, strings.ToLower(identitySerial)},
		{"serial-leading-space", identitySerial, " " + identitySerial},
		{"serial-trailing-space", identitySerial, identitySerial + " "},
		{"serial-control", identitySerial, `SYNTHETIC\nATA`},
		{"serial-unicode", identitySerial, "SYNTHETIC-é"},
		{"serial-empty", identitySerial, ""},
		{"serial-overlong", identitySerial, strings.Repeat("A", 21)},
		{"missing-wwn", `"wwn"`, `"other_wwn"`},
		{"wwn-null", `"wwn":{"naa":5,"oui":11259375,"id":4886718345}`, `"wwn":null`},
		{"wwn-scalar", `"wwn":{"naa":5,"oui":11259375,"id":4886718345}`, `"wwn":"5abcdef123456789"`},
		{"missing-naa", `"naa"`, `"other_naa"`},
		{"naa-other", `"naa":5`, `"naa":6`},
		{"naa-overflow", `"naa":5`, `"naa":16`},
		{"oui-overflow", `"oui":11259375`, `"oui":16777216`},
		{"id-overflow", `"id":4886718345`, `"id":68719476736`},
		{"id-different", `"id":4886718345`, `"id":4886718346`},
		{"id-null", `"id":4886718345`, `"id":null`},
		{"id-string", `"id":4886718345`, `"id":"4886718345"`},
		{"id-exponent", `"id":4886718345`, `"id":4886718345e0`},
		{"id-fraction", `"id":4886718345`, `"id":4886718345.0`},
		{"id-negative", `"id":4886718345`, `"id":-1`},
		{"id-negative-zero", `"id":4886718345`, `"id":-0`},
		{"id-bigint", `"id":4886718345`, `"id":18446744073709551616`},
		{"non-ATA", `"protocol":"ATA"`, `"protocol":"SCSI"`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			input := strings.Replace(good, tc.from, tc.to, 1)
			if input == good {
				t.Fatal("fixture mutation did not apply")
			}
			got, err := ParseMatchingATAIdentity([]byte(input), 0, identitySerial, identityWWN)
			if !errors.Is(err, ErrIdentity) || got != (Observation{}) || err.Error() != ErrIdentity.Error() {
				t.Fatal("invalid identity admitted or leaked details", err)
			}
		})
	}
}

func TestIdentityComparisonKeepsWholeReportBoundsAndRefusals(t *testing.T) {
	good := identityFixture(0)
	for _, input := range []string{
		good + "{}",
		strings.Replace(good, `"serial_number":`, `"serial_number":"other","serial_number":`, 1),
		strings.Replace(good, `"id":4886718345`, `"id":4886718345,"ID":4886718345`, 1),
		strings.Replace(good, `"id":4886718345`, `"id":4886718345,"\u0069d":4886718345`, 1),
		strings.Replace(good, `"serial_number":`, `"SERIAL_NUMBER":"other","serial_number":`, 1),
		strings.Replace(good, `"passed":true`, `"passed":false`, 1),
		strings.Replace(good, `"version":[7,4]`, `"version":[7,6]`, 1),
		strings.Replace(good, `"text"`, `"\ud800"`, 1),
		good + strings.Repeat(" ", MaxBytes),
	} {
		plain, plainErr := Parse([]byte(input), 0)
		matched, err := ParseMatchingATAIdentity([]byte(input), 0, identitySerial, identityWWN)
		if plain != (Observation{}) || plainErr == nil || matched != (Observation{}) || !errors.Is(err, plainErr) {
			t.Fatal("identity path bypassed original whole-report refusal")
		}
	}
	for _, exit := range []int{-1, 1, 256} {
		if got, err := ParseMatchingATAIdentity([]byte(good), exit, identitySerial, identityWWN); got != (Observation{}) || err == nil {
			t.Fatal("identity bypassed independent exit validation")
		}
	}
}

func TestIdentityComparisonNarrowExpectedProfileAndExactBitAssembly(t *testing.T) {
	for _, serial := range []string{"", " ", " leading", "trailing ", "line\nbreak", "nul\x00byte", "non-ascii-é", strings.Repeat("A", 21)} {
		if got, err := ParseMatchingATAIdentity(nil, 0, serial, identityWWN); got != (Observation{}) || !errors.Is(err, ErrIdentity) {
			t.Fatal("invalid expected serial used report data as fallback")
		}
	}
	for _, wwn := range []uint64{0, 0x4abcdef123456789, 0x6abcdef123456789, ^uint64(0)} {
		if got, err := ParseMatchingATAIdentity(nil, 0, identitySerial, wwn); got != (Observation{}) || !errors.Is(err, ErrIdentity) {
			t.Fatal("invalid expected WWN used report data as fallback")
		}
	}
	for _, wwn := range []uint64{0x5000000000000000, identityWWN, 0x5fffffffffffffff} {
		serial := "EXACT space 01"
		input := strings.Replace(identityFixture(0), identitySerial, serial, 1)
		input = strings.Replace(input, `"wwn":{"naa":5,"oui":11259375,"id":4886718345}`,
			fmt.Sprintf(`"wwn":{"naa":5,"oui":%d,"id":%d}`, (wwn>>36)&0xffffff, wwn&0xfffffffff), 1)
		if got, err := ParseMatchingATAIdentity([]byte(input), 0, serial, wwn); err != nil || got.Assessment() != ReportedPass {
			t.Fatal("64-bit WWN or exact internal spaces changed", err)
		}
		if got, err := ParseMatchingATAIdentity([]byte(input), 0, serial, wwn^1); got != (Observation{}) || !errors.Is(err, ErrIdentity) {
			t.Fatal("one-bit changed WWN admitted")
		}
	}
}

func TestIdentityComparisonNeverUpgradesUncertainOrDisabledEvidence(t *testing.T) {
	for _, fields := range []string{
		`"smart_support":{"available":true,"enabled":false}`,
		`"smart_support":{"available":false}`,
	} {
		input := strings.Replace(identityFixture(0), `"smart_support":{"available":true,"enabled":true},"smart_status":{"passed":true}`, fields, 1)
		plain, err := Parse([]byte(input), 0)
		if err != nil || plain.Assessment() != NoAssessment {
			t.Fatal("invalid disabled/unsupported fixture")
		}
		got, err := ParseMatchingATAIdentity([]byte(input), 0, identitySerial, identityWWN)
		if err != nil || got != plain {
			t.Fatal("matching identity upgraded non-health evidence")
		}
		input = strings.Replace(input, `"serial_number":`, `"missing_serial":`, 1)
		if got, err := ParseMatchingATAIdentity([]byte(input), 0, identitySerial, identityWWN); got != (Observation{}) || !errors.Is(err, ErrIdentity) {
			t.Fatal("disabled/unsupported path skipped attribution comparison")
		}
	}
	// A normal unavailable report remains valid for Parse, but supplies neither
	// a report identity nor evidence authorizing association with a specific disk.
	input := `{"json_format_version":[1,0],"smartctl":{"version":[7,5],"pre_release":false,"exit_status":2}}`
	if plain, err := Parse([]byte(input), 2); err != nil || plain.State() != Unavailable {
		t.Fatal("invalid unavailable fixture")
	}
	if got, err := ParseMatchingATAIdentity([]byte(input), 2, identitySerial, identityWWN); got != (Observation{}) || !errors.Is(err, ErrIdentity) {
		t.Fatal("unattributed open/power failure became a per-disk report")
	}
}

func FuzzATAIdentityComparison(f *testing.F) {
	f.Add([]byte(identityFixture(0)), 0)
	f.Add([]byte(identityFixture(12)), 12)
	f.Add([]byte(`{"wwn":{"id":1e1000}}`), 0)
	f.Fuzz(func(t *testing.T, data []byte, exit int) {
		got, err := ParseMatchingATAIdentity(data, exit, identitySerial, identityWWN)
		if err != nil {
			if got != (Observation{}) {
				t.Fatal("identity refusal leaked observation")
			}
			return
		}
		plain, err := Parse(data, exit)
		if err != nil || plain != got {
			t.Fatal("matching bypassed baseline projection")
		}
		var independent struct {
			Serial string                        `json:"serial_number"`
			Device struct{ Protocol string }     `json:"device"`
			WWN    struct{ NAA, OUI, ID uint64 } `json:"wwn"`
		}
		if json.Unmarshal(data, &independent) != nil || independent.Serial != identitySerial || independent.Device.Protocol != "ATA" ||
			independent.WWN.NAA != 5 || independent.WWN.OUI != 0xabcdef || independent.WWN.ID != 0x123456789 {
			t.Fatal("comparison success did not match independent field oracle")
		}
	})
}
