// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartreport

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func fixture(exit int, passed bool) string {
	return fmt.Sprintf(`{"json_format_version":[1,0],"smartctl":{"version":[7,4],"pre_release":false,"exit_status":%d,"messages":[{"string":"PRIVATE-MESSAGE"}]},"device":{"name":"/dev/PRIVATE-DEVICE","protocol":"ATA"},"model_name":"PRIVATE-MODEL","serial_number":"PRIVATE-SERIAL","wwn":{"id":1234},"smart_support":{"available":true,"enabled":true},"smart_status":{"passed":%t},"unknown":{"ignored":null,"nested":[1,true,"text"]}}`, exit, passed)
}

func TestATAExitBitsAndAssessment(t *testing.T) {
	// Synthetic exhaustive mapping, not proof of real transport/check coverage.
	for exit := 0; exit < 256; exit++ {
		t.Run(fmt.Sprint(exit), func(t *testing.T) {
			o, err := Parse([]byte(fixture(exit, exit&8 == 0)), exit)
			if err != nil {
				t.Fatal(err)
			}
			wantState := Complete
			if exit&7 != 0 {
				wantState = Partial
			}
			wantAssessment := ReportedPass
			if exit&8 != 0 {
				wantAssessment = ReportedFail
			}
			wantFlags := Flags{exit&1 != 0, exit&2 != 0, exit&4 != 0, exit&8 != 0, exit&16 != 0, exit&32 != 0, exit&64 != 0, exit&128 != 0}
			if o.State() != wantState || o.Assessment() != wantAssessment || o.Flags() != wantFlags {
				t.Fatalf("wrong projection: %#v", o)
			}
		})
	}
}

func TestUnobservedAndUnsupportedStates(t *testing.T) {
	base := `{"json_format_version":[1,0],"smartctl":{"version":[7,4],"pre_release":false,"exit_status":%d}%s}`
	cases := []struct {
		name   string
		exit   int
		fields string
		state  State
	}{
		{"open-or-power-no-device", 2, "", Unavailable},
		{"command-failed", 1, "", Unavailable},
		{"SMART-command-no-result", 4, `,"device":{"protocol":"ATA"},"smart_support":{"available":true,"enabled":true}`, Unavailable},
		{"capability-absent", 4, `,"device":{"protocol":"ATA"},"smart_support":{"available":false}`, UnsupportedSMART},
		{"disabled", 4, `,"device":{"protocol":"ATA"},"smart_support":{"available":true,"enabled":false}`, Disabled},
		{"SCSI", 0, `,"device":{"protocol":"SCSI"},"smart_status":{"passed":true}`, UnsupportedProtocol},
		{"NVMe-with-exit-flags", 128, `,"device":{"protocol":"NVMe"},"smart_status":{"passed":true}`, UnsupportedProtocol},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Parse([]byte(fmt.Sprintf(base, tc.exit, tc.fields)), tc.exit)
			if err != nil || o.State() != tc.state || o.Assessment() != NoAssessment {
				t.Fatalf("unexpected: %#v %v", o, err)
			}
			if tc.state == UnsupportedProtocol && o.Flags() != (Flags{}) {
				t.Fatal("interpreted non-ATA exit flags")
			}
		})
	}
}

func TestRejectInvalidAndAmbiguousReports(t *testing.T) {
	good := fixture(0, true)
	cases := []struct {
		name, input string
		exit        int
		want        error
	}{
		{"empty", "", 0, ErrInvalid},
		{"null-root", "null", 0, ErrInvalid},
		{"array-root", "[]", 0, ErrInvalid},
		{"truncated", good[:len(good)-1], 0, ErrInvalid},
		{"trailing", good + " {}", 0, ErrInvalid},
		{"invalid-utf8", good + string([]byte{0xff}), 0, ErrInvalid},
		{"duplicate-known", strings.Replace(good, `"passed":true`, `"passed":true,"passed":false`, 1), 0, ErrInvalid},
		{"case-alias", strings.Replace(good, `"passed":true`, `"passed":true,"Passed":false`, 1), 0, ErrInvalid},
		{"escaped-duplicate", strings.Replace(good, `"passed":true`, `"passed":true,"\u0070assed":false`, 1), 0, ErrInvalid},
		{"unknown-duplicate", strings.Replace(good, `"ignored":null`, `"ignored":null,"ignored":1`, 1), 0, ErrInvalid},
		{"unknown-surrogate", strings.Replace(good, `"text"`, `"\ud800"`, 1), 0, ErrInvalid},
		{"known-null", strings.Replace(good, `"passed":true`, `"passed":null`, 1), 0, ErrInvalid},
		{"known-string-bool", strings.Replace(good, `"passed":true`, `"passed":"true"`, 1), 0, ErrInvalid},
		{"wrong-key-case", strings.Replace(good, `"smart_status"`, `"SMART_STATUS"`, 1), 0, ErrInvalid},
		{"false-without-fail-bit", fixture(0, false), 0, ErrInvalid},
		{"pass-with-fail-bit", fixture(8, true), 8, ErrInvalid},
		{"exit-mismatch", good, 64, ErrInvalid},
		{"signal-not-exit", good, -1, ErrInvalid},
		{"too-large-exit", fixture(256, true), 256, ErrInvalid},
		{"fraction-exit", strings.Replace(good, `"exit_status":0`, `"exit_status":0.0`, 1), 0, ErrInvalid},
		{"exponent-exit", strings.Replace(good, `"exit_status":0`, `"exit_status":0e0`, 1), 0, ErrInvalid},
		{"tool-null", strings.Replace(good, `"version":[7,4]`, `"version":null`, 1), 0, ErrInvalid},
		{"device-null", strings.Replace(good, `{"name":"/dev/PRIVATE-DEVICE","protocol":"ATA"}`, `null`, 1), 0, ErrInvalid},
		{"support-contradiction", strings.Replace(good, `"available":true`, `"available":false`, 1), 0, ErrInvalid},
		{"disabled-with-status", strings.Replace(good, `"enabled":true`, `"enabled":false`, 1), 0, ErrInvalid},
		{"missing-support-field", strings.Replace(good, `"enabled":true`, `"other":true`, 1), 0, ErrInvalid},
		{"no-assessment-success", strings.Replace(good, `,"smart_status":{"passed":true}`, "", 1), 0, ErrInvalid},
		{"new-format", strings.Replace(good, `[1,0]`, `[2,0]`, 1), 0, ErrUnsupportedFormat},
		{"new-version", strings.Replace(good, `[7,4]`, `[7,5]`, 1), 0, ErrUnsupportedFormat},
		{"patch-version", strings.Replace(good, `[7,4]`, `[7,4,1]`, 1), 0, ErrInvalid},
		{"pre-release", strings.Replace(good, `"pre_release":false`, `"pre_release":true`, 1), 0, ErrUnsupportedFormat},
		{"bytes-limit", strings.Repeat(" ", MaxBytes) + good, 0, ErrInvalid},
		{"depth-limit", strings.Replace(good, `"text"`, strings.Repeat("[", 16)+"0"+strings.Repeat("]", 16), 1), 0, ErrInvalid},
		{"token-limit", strings.Replace(good, `"text"`, "["+strings.Repeat("0,", maxTokens)+"0]", 1), 0, ErrInvalid},
		{"string-limit", strings.Replace(good, `"text"`, `"`+strings.Repeat("x", maxString+1)+`"`, 1), 0, ErrInvalid},
		{"key-limit", strings.Replace(good, `"ignored"`, `"`+strings.Repeat("x", maxKey+1)+`"`, 1), 0, ErrInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o, err := Parse([]byte(tc.input), tc.exit)
			if !errors.Is(err, tc.want) || o != (Observation{}) {
				t.Fatalf("non-atomic refusal: %#v %v", o, err)
			}
			if err.Error() != tc.want.Error() {
				t.Fatal("non-redacted error")
			}
		})
	}
}

func TestRedactionAndInputNotRetained(t *testing.T) {
	input := []byte(fixture(64, true))
	o, err := Parse(input, 64)
	if err != nil {
		t.Fatal(err)
	}
	for i := range input {
		input[i] = 0
	}
	if o.Assessment() != ReportedPass || !o.Flags().ErrorLogRecords {
		t.Fatal("input buffer retained")
	}
	if strings.Contains(fmt.Sprintf("%+v", o), "PRIVATE") {
		t.Fatal("private metadata retained")
	}
	if _, err := json.Marshal(o); !errors.Is(err, ErrPrivate) {
		t.Fatal("serialized internal observation")
	}
	before := o
	if err := json.Unmarshal([]byte(`{"state":1}`), &o); !errors.Is(err, ErrPrivate) || o != before {
		t.Fatal("JSON can create or replace an observation")
	}
	// The structural test prevents adding an overlooked retained pointer/string.
	typ := reflect.TypeOf(o)
	for i := 0; i < typ.NumField(); i++ {
		if typ.Field(i).Type.Kind() != reflect.Uint8 {
			t.Fatal("observation gained raw or unbounded fields")
		}
	}
	var zero Observation
	if zero.State() != NotObserved || zero.Assessment() != NoAssessment || zero.Flags() != (Flags{}) {
		t.Fatal("zero observation reassuring")
	}
}

func FuzzParse(f *testing.F) {
	f.Add([]byte(fixture(0, true)), 0)
	f.Add([]byte(fixture(12, false)), 12)
	f.Add([]byte(`{"json_format_version":[1,0],"smartctl":{"version":[7,4],"pre_release":false,"exit_status":2}}`), 2)
	f.Fuzz(func(t *testing.T, data []byte, exit int) {
		o, err := Parse(data, exit)
		if err != nil && (o != (Observation{}) || (err != ErrInvalid && err != ErrUnsupportedFormat)) {
			t.Fatal("non-atomic/unredacted refusal")
		}
		if err == nil {
			if o.State() == NotObserved || o.State() > Disabled {
				t.Fatal("invalid success state")
			}
			if _, err := json.Marshal(o); !errors.Is(err, ErrPrivate) {
				t.Fatal("raw observation serializable")
			}
		}
	})
}
