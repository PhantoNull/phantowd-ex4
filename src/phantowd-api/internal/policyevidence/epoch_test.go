// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"
)

func epochFixture(t *testing.T) ([]byte, []byte, []byte) {
	t.Helper()
	base, current := policy(t, 7), policy(t, 8)
	o, err := DeclareEpochOpening(installation, operation, math.MaxUint64, base)
	if err != nil {
		t.Fatal(err)
	}
	opening, err := EncodeEpochOpening(o)
	if err != nil {
		t.Fatal(err)
	}
	c, err := DeclareEpochClosure(opening, current)
	if err != nil {
		t.Fatal(err)
	}
	closing, err := EncodeEpochClosure(c)
	if err != nil {
		t.Fatal(err)
	}
	return opening, closing, current
}

func TestEpochRecordMatchingNeverAuthorizesBoot(t *testing.T) {
	opening, closing, current := epochFixture(t)
	for _, tc := range []struct {
		name                 string
		open, close, current Slot
		want                 EpochKind
	}{
		{"no evidence", Slot{State: Absent}, Slot{State: Absent}, Slot{Present, current}, NoEpochRecorded},
		{"open", Slot{Present, opening}, Slot{State: Absent}, Slot{Present, current}, OpenEpochObserved},
		{"matching declarations", Slot{Present, opening}, Slot{Present, closing}, Slot{Present, current}, ClosureMatchesCurrent},
		{"orphan closure", Slot{State: Absent}, Slot{Present, closing}, Slot{Present, current}, InconsistentEpochEvidence},
		{"unknown opening", Slot{}, Slot{Present, closing}, Slot{Present, current}, IncompleteEpochEvidence},
		{"missing current", Slot{Present, opening}, Slot{Present, closing}, Slot{State: Absent}, IncompleteEpochEvidence},
		{"exact current changed", Slot{Present, opening}, Slot{Present, closing}, Slot{Present, append(bytes.Clone(current), '\n')}, InconsistentEpochEvidence},
		{"exact opening changed", Slot{Present, append(bytes.Clone(opening), '\n')}, Slot{Present, closing}, Slot{Present, current}, InconsistentEpochEvidence},
		{"older current", Slot{Present, opening}, Slot{State: Absent}, Slot{Present, policy(t, 6)}, InconsistentEpochEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d, err := MatchEpoch(installation, tc.open, tc.close, tc.current)
			if err != nil || d.Kind() != tc.want {
				t.Fatalf("unexpected redacted diagnosis: %v %v", d, err)
			}
			if _, err := json.Marshal(d); !errors.Is(err, ErrPrivate) {
				t.Fatal("generic JSON admitted")
			}
			if strings.Contains(fmt.Sprintf("%#v", d), installation) {
				t.Fatal("private identity formatted")
			}
		})
	}
}

func TestEpochMalformedPresentEvidenceCannotHideBehindMissingInput(t *testing.T) {
	opening, closing, current := epochFixture(t)
	for _, bad := range [][]byte{[]byte(`{}`), append(bytes.Clone(opening), []byte(`{}`)...), bytes.Repeat([]byte(" "), MaxRecordBytes+1)} {
		if d, err := MatchEpoch(installation, Slot{Present, bad}, Slot{}, Slot{}); err != ErrInvalid || d != (EpochDiagnosis{}) {
			t.Fatal("malformed opening hidden by missing data")
		}
	}
	if d, err := MatchEpoch(installation, Slot{}, Slot{Present, []byte(`{}`)}, Slot{Present, current}); err != ErrInvalid || d != (EpochDiagnosis{}) {
		t.Fatal("malformed closure hidden")
	}
	if d, err := MatchEpoch(installation, Slot{Present, opening}, Slot{Present, closing}, Slot{Present, []byte(`{}`)}); err != ErrInvalid || d != (EpochDiagnosis{}) {
		t.Fatal("malformed current admitted")
	}
}

func TestEpochStrictCodecsBoundsAndPrivacy(t *testing.T) {
	opening, closing, _ := epochFixture(t)
	for _, closure := range []bool{false, true} {
		wire := opening
		if closure {
			wire = closing
		}
		check := func(data []byte) bool {
			if closure {
				r, err := DecodeEpochClosure(bytes.NewReader(data))
				return err == ErrInvalid && r == (EpochClosure{})
			}
			r, err := DecodeEpochOpening(bytes.NewReader(data))
			return err == ErrInvalid && r == (EpochOpening{})
		}
		for _, data := range [][]byte{
			[]byte(`{}`), append(bytes.Clone(wire), []byte(`{}`)...), append(bytes.Clone(wire), 0xff),
			[]byte(strings.Replace(string(wire), `"schema_version":1`, `"schema_version":2`, 1)),
			[]byte(strings.Replace(string(wire), `"sequence":18446744073709551615`, `"sequence":18446744073709551616`, 1)),
			[]byte(strings.Replace(string(wire), `"sequence":18446744073709551615`, `"sequence":0`, 1)),
			[]byte(strings.Replace(string(wire), `"sequence":18446744073709551615`, `"sequence":1.0`, 1)),
			[]byte(strings.Replace(string(wire), `"epoch_id"`, `"Epoch_ID"`, 1)),
			[]byte(strings.Replace(string(wire), operation, strings.Repeat("0", 32), 1)),
			[]byte(strings.Replace(string(wire), operation, `\ud800`, 1)),
			[]byte(strings.Replace(string(wire), `"format":`, `"extra":true,"format":`, 1)),
			[]byte(strings.Replace(string(wire), `"format":`, `"format":"duplicate","format":`, 1)),
			[]byte(strings.Replace(string(wire), `"sequence":18446744073709551615`, `"sequence":null`, 1)),
		} {
			if !check(data) {
				t.Fatal("invalid epoch encoding admitted")
			}
		}
		var fields map[string]json.RawMessage
		if json.Unmarshal(wire, &fields) != nil {
			t.Fatal("fixture")
		}
		for key := range fields {
			copyFields := make(map[string]json.RawMessage, len(fields))
			for k, v := range fields {
				if k != key {
					copyFields[k] = v
				}
			}
			bad, err := json.Marshal(copyFields)
			if err != nil || !check(bad) {
				t.Fatal("missing field admitted")
			}
		}
		padded := append(bytes.Clone(wire), bytes.Repeat([]byte(" "), MaxRecordBytes-len(wire))...)
		if closure {
			if _, err := DecodeEpochClosure(bytes.NewReader(padded)); err != nil {
				t.Fatal("inclusive closure byte bound refused")
			}
		} else if _, err := DecodeEpochOpening(bytes.NewReader(padded)); err != nil {
			t.Fatal("inclusive opening byte bound refused")
		}
		if !check(append(padded, ' ')) {
			t.Fatal("record byte bound exceeded")
		}
	}
	o, err := DecodeEpochOpening(bytes.NewReader(opening))
	if err != nil {
		t.Fatal(err)
	}
	c, err := DecodeEpochClosure(bytes.NewReader(closing))
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []any{o, c, EpochOpening{}, EpochClosure{}} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivate) {
			t.Fatal("generic record encoding admitted")
		}
		if strings.Contains(fmt.Sprintf("%#v", value), installation) {
			t.Fatal("private record formatted")
		}
	}
	if _, err := DecodeEpochOpening(nil); err != ErrInvalid {
		t.Fatal("nil reader admitted")
	}
	if _, err := DecodeEpochClosure(nil); err != ErrInvalid {
		t.Fatal("nil reader admitted")
	}
	if _, err := EncodeEpochOpening(EpochOpening{}); err != ErrInvalid {
		t.Fatal("zero opening encoded")
	}
	if _, err := EncodeEpochClosure(EpochClosure{}); err != ErrInvalid {
		t.Fatal("zero closure encoded")
	}
	if _, err := DeclareEpochClosure(opening, policy(t, 6)); err != ErrInvalid {
		t.Fatal("revision rollback declared")
	}
	if _, err := DeclareEpochClosure(opening, append(policy(t, 7), '\n')); err != ErrInvalid {
		t.Fatal("same-revision byte change declared")
	}
}

func TestEpochForeignAndMismatchedDeclarations(t *testing.T) {
	opening, closing, current := epochFixture(t)
	for _, change := range []func(*epochRecord){
		func(r *epochRecord) { r.InstallationID = operation },
		func(r *epochRecord) { r.EpochID = installation },
		func(r *epochRecord) { r.Sequence-- },
		func(r *epochRecord) { r.OpeningSHA256 = strings.Repeat("0", 64) },
		func(r *epochRecord) { r.PolicyRevision = 6 },
	} {
		c, err := DecodeEpochClosure(bytes.NewReader(closing))
		if err != nil {
			t.Fatal(err)
		}
		change(&c.value)
		wire, err := EncodeEpochClosure(c)
		if err != nil {
			t.Fatal(err)
		}
		d, err := MatchEpoch(installation, Slot{Present, opening}, Slot{Present, wire}, Slot{Present, current})
		if err != nil || d.Kind() != InconsistentEpochEvidence {
			t.Fatal("mismatched epoch declarations accepted")
		}
	}
}

func FuzzEpochRecordDecoders(f *testing.F) {
	o, err := DeclareEpochOpening(installation, operation, 1, []byte(policyFixture))
	if err != nil {
		f.Fatal(err)
	}
	opening, err := EncodeEpochOpening(o)
	if err != nil {
		f.Fatal(err)
	}
	c, err := DeclareEpochClosure(opening, []byte(policyFixture))
	if err != nil {
		f.Fatal(err)
	}
	closing, err := EncodeEpochClosure(c)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(opening)
	f.Add(closing)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > MaxRecordBytes+1 {
			return
		}
		if o, err := DecodeEpochOpening(bytes.NewReader(data)); err == nil {
			wire, err := EncodeEpochOpening(o)
			if err != nil {
				t.Fatal(err)
			}
			back, err := DecodeEpochOpening(bytes.NewReader(wire))
			if err != nil || back != o {
				t.Fatal("opening roundtrip")
			}
		} else if err != ErrInvalid {
			t.Fatal("nonconstant error")
		}
		if c, err := DecodeEpochClosure(bytes.NewReader(data)); err == nil {
			wire, err := EncodeEpochClosure(c)
			if err != nil {
				t.Fatal(err)
			}
			back, err := DecodeEpochClosure(bytes.NewReader(wire))
			if err != nil || back != c {
				t.Fatal("closure roundtrip")
			}
		} else if err != ErrInvalid {
			t.Fatal("nonconstant error")
		}
	})
}
