// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package tests for the internal Samba enrollment journal.
package smbprovision

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

var testAccount = serviceaccounts.Account{
	ID: "reader", Name: "qreader", UID: 22000, GID: 22000, State: serviceaccounts.Disabled,
}

func validJournal(phase string, revision uint64, sid string) Journal {
	return Journal{Format: Format, SchemaVersion: 1, Revision: revision, NativeRevision: 5,
		Account: testAccount, SID: sid, Phase: phase}
}

func TestJournalPhasesAndSecretBoundary(t *testing.T) {
	for _, item := range []struct {
		phase    string
		revision uint64
		sid      string
	}{
		{Reserved, 1, ""}, {CreateIntent, 2, ""},
		{DisabledNoPassword, 3, "S-1-5-21-1-2-3-1001"},
		{PasswordIntent, 4, "S-1-5-21-1-2-3-1001"},
		{CredentialSetDisabled, 5, "S-1-5-21-1-2-3-1001"},
		{EnableIntent, 6, "S-1-5-21-1-2-3-1001"}, {Enabled, 7, "S-1-5-21-1-2-3-1001"},
		{ReviewRequired, 2, ""}, {ReviewRequired, 3, ""}, {ReviewRequired, 3, "S-1-5-21-1-2-3-1001"},
		{ReviewRequired, 4, "S-1-5-21-1-2-3-1001"}, {ReviewRequired, 6, "S-1-5-21-1-2-3-1001"},
		{ReviewRequired, 7, "S-1-5-21-1-2-3-1001"},
	} {
		if err := validJournal(item.phase, item.revision, item.sid).Validate(); err != nil {
			t.Fatalf("valid phase %s/%d rejected: %v", item.phase, item.revision, err)
		}
	}
	for _, item := range []struct {
		name string
		j    Journal
	}{
		{"revision skips", validJournal(PasswordIntent, 5, "S-1-5-21-1-2-3-1001")},
		{"missing SID", validJournal(DisabledNoPassword, 3, "")},
		{"missing enable-intent SID", validJournal(EnableIntent, 6, "")},
		{"wrong enabled revision", validJournal(Enabled, 6, "S-1-5-21-1-2-3-1001")},
		{"review missing enabled SID", validJournal(ReviewRequired, 7, "")},
		{"malformed SID", validJournal(CredentialSetDisabled, 5, "S-1-5-21-1-2-3-0")},
		{"enabled account", func() Journal {
			j := validJournal(Reserved, 1, "")
			j.Account.State = serviceaccounts.Enabled
			return j
		}()},
		{"secret in wrong field", func() Journal { j := validJournal(Reserved, 1, ""); j.SID = "public-qemu-secret"; return j }()},
	} {
		t.Run(item.name, func(t *testing.T) {
			if item.j.Validate() == nil {
				t.Fatal("invalid journal accepted")
			}
		})
	}
	encoded, err := json.Marshal(validJournal(CredentialSetDisabled, 5, "S-1-5-21-1-2-3-1001"))
	if err != nil || bytes.Contains(encoded, []byte("password")) || bytes.Contains(encoded, []byte("hash")) {
		t.Fatal("journal serialized credential material", string(encoded), err)
	}
}

func TestDecodeRejectsSecretAndUnknownFields(t *testing.T) {
	base, err := json.Marshal(validJournal(Reserved, 1, ""))
	if err != nil {
		t.Fatal(err)
	}
	valid, err := Decode(bytes.NewReader(base))
	if err != nil || valid.Phase != Reserved {
		t.Fatal("valid journal rejected", valid, err)
	}
	for _, input := range []string{
		strings.TrimSuffix(string(base), "}") + `,"password":"never-persist"}`,
		strings.TrimSuffix(string(base), "}") + `,"nt_hash":"forbidden"}`,
		`{"format":"phantowd-smb-provision","schema_version":1,"revision":1,"native_revision":5,"account":{"id":"reader","name":"qreader","uid":22000,"gid":22000,"state":"disabled"},"phase":"reserved","future":true}`,
		`{"format":"phantowd-smb-provision","schema_version":1,"revision":1,"native_revision":5,"account":{"id":"reader","name":"qreader","uid":22000,"gid":22000,"state":"disabled"},"phase":"reserved","phase":"password-intent"}`,
	} {
		if j, err := Decode(strings.NewReader(input)); err == nil || j != (Journal{}) {
			t.Fatal("unsafe or ambiguous document accepted", j, err)
		}
	}
}

func TestValidPasswordBoundedStdinLine(t *testing.T) {
	for _, tc := range []struct {
		name   string
		secret []byte
		valid  bool
	}{
		{"normal", []byte("a-secure-plaintext"), true},
		{"unicode", []byte("segreto-è-lungo"), true},
		{"too short", []byte("short"), false},
		{"too long", bytes.Repeat([]byte("x"), MaxPasswordBytes+1), false},
		{"newline", []byte("long-enough\nnext"), false},
		{"carriage return", []byte("long-enough\rnext"), false},
		{"tab", []byte("long-enough\tnext"), false},
		{"nul", []byte("long-enough\x00next"), false},
		{"invalid utf8", append(bytes.Repeat([]byte("x"), MinPasswordBytes), 0xff), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ValidPassword(tc.secret); got != tc.valid {
				t.Fatalf("ValidPassword()=%t want %t", got, tc.valid)
			}
		})
	}
}

func TestObservationMustBindTheExactAccountAndRequestedState(t *testing.T) {
	if err := (Observation{}).validateFor(testAccount, true); err != nil {
		t.Fatal("explicit absence refused", err)
	}
	valid := Observation{Present: true, Name: testAccount.Name, UID: testAccount.UID,
		GID: testAccount.GID, SID: "S-1-5-21-1-2-3-1001", Disabled: true}
	if err := valid.validateFor(testAccount, true); err != nil {
		t.Fatal("exact disabled account refused", err)
	}
	enabled := valid
	enabled.Disabled = false
	if err := enabled.validateFor(testAccount, false); err != nil {
		t.Fatal("exact enabled account refused", err)
	}
	for _, invalid := range []Observation{
		{Present: true, Name: "other", UID: testAccount.UID, GID: testAccount.GID, SID: valid.SID, Disabled: true},
		{Present: true, Name: testAccount.Name, UID: testAccount.UID + 1, GID: testAccount.GID, SID: valid.SID, Disabled: true},
		{Present: true, Name: testAccount.Name, UID: testAccount.UID, GID: testAccount.GID, SID: "S-1-5-21-1-2-3-0", Disabled: true},
		{Present: true, Name: testAccount.Name, UID: testAccount.UID, GID: testAccount.GID, SID: valid.SID, Disabled: false},
		{Present: false, Name: testAccount.Name},
	} {
		if err := invalid.validateFor(testAccount, true); err == nil {
			t.Fatal("mismatched passdb observation accepted", invalid)
		}
	}
}

func TestJournalValidatesReadOnlyPassdbEvidenceWithoutRecoveringIntents(t *testing.T) {
	sid := "S-1-5-21-1-2-3-1001"
	disabled := Observation{Present: true, Name: testAccount.Name, UID: testAccount.UID,
		GID: testAccount.GID, SID: sid, Disabled: true}
	enabled := disabled
	enabled.Disabled = false
	wrongSID := enabled
	wrongSID.SID = "S-1-5-21-1-2-3-1002"
	for _, test := range []struct {
		name        string
		journal     Journal
		observation Observation
		want        error
	}{
		{"reserved absent", validJournal(Reserved, 1, ""), Observation{}, nil},
		{"reserved unexpectedly present", validJournal(Reserved, 1, ""), disabled, ErrObservation},
		{"confirmed disabled", validJournal(CredentialSetDisabled, 5, sid), disabled, nil},
		{"confirmed disabled but passdb enabled", validJournal(CredentialSetDisabled, 5, sid), enabled, ErrObservation},
		{"confirmed enabled", validJournal(Enabled, 7, sid), enabled, nil},
		{"confirmed enabled but passdb disabled", validJournal(Enabled, 7, sid), disabled, ErrObservation},
		{"review remains observable", validJournal(ReviewRequired, 7, sid), enabled, nil},
		{"review SID mismatch", validJournal(ReviewRequired, 7, sid), wrongSID, ErrObservation},
		{"intent is refused without recovery", validJournal(EnableIntent, 6, sid), disabled, ErrReview},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.journal.ValidateObservation(test.observation); !errors.Is(err, test.want) {
				t.Fatalf("ValidateObservation error = %v, want %v", err, test.want)
			}
		})
	}
}

func FuzzDecode(f *testing.F) {
	base, _ := json.Marshal(validJournal(Reserved, 1, ""))
	f.Add(base)
	f.Add([]byte(`{"format":"phantowd-smb-provision","schema_version":1,"revision":1,"native_revision":5,"account":{"id":"reader","name":"qreader","uid":22000,"gid":22000,"state":"disabled"},"phase":"reserved"}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		journal, err := Decode(bytes.NewReader(input))
		if err != nil && journal != (Journal{}) {
			t.Fatal("partial journal returned on failure")
		}
		if err == nil && journal.Validate() != nil {
			t.Fatal("decoder returned invalid journal")
		}
	})
}
