// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityprovision

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func fixtureRegistry(t testing.TB) serviceaccounts.Registry {
	t.Helper()
	r, err := serviceaccounts.New(21000, 21000)
	if err != nil {
		t.Fatal(err)
	}
	r, err = r.Create(1, "fixture", "qpjournal", serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func fixtureJournal(t testing.TB) Journal {
	r := fixtureRegistry(t)
	return Journal{Format: Format, SchemaVersion: 1, Revision: 1, RegistryRevision: r.Revision, Account: r.Accounts[0], Phase: Reserved}
}

func TestJournalSchema(t *testing.T) {
	j := fixtureJournal(t)
	data, _ := json.Marshal(j)
	got, err := Decode(bytes.NewReader(data))
	if err != nil || got != j {
		t.Fatal(got, err)
	}
	for _, mutate := range []func(*Journal){
		func(j *Journal) { j.Format = "other" }, func(j *Journal) { j.SchemaVersion++ },
		func(j *Journal) { j.RegistryRevision = 0 }, func(j *Journal) { j.Account.State = serviceaccounts.Enabled },
		func(j *Journal) { j.Account.UID = 0 }, func(j *Journal) { j.Account.GID++ },
		func(j *Journal) { j.Phase = "done" }, func(j *Journal) { j.Revision = 2 },
	} {
		bad := j
		mutate(&bad)
		data, _ := json.Marshal(bad)
		if _, err := Decode(bytes.NewReader(data)); err == nil {
			t.Fatal("invalid journal accepted", bad)
		}
	}
	for phase, revision := range map[string]uint64{Reserved: 1, GroupIntent: 2, GroupConfirmed: 3, UserIntent: 4, UnixConfirmed: 5, ReviewRequired: 6} {
		j.Phase, j.Revision = phase, revision
		if j.Validate() != nil {
			t.Fatal(phase)
		}
	}
	for _, input := range []string{"null", "{}", string(data) + "{}", strings.Replace(string(data), `"phase":`, `"unknown":`, 1), strings.Repeat(" ", MaxBytes+1)} {
		if _, err := Decode(strings.NewReader(input)); err == nil {
			t.Fatal("malformed JSON accepted")
		}
	}
	if _, err := Decode(nil); err == nil {
		t.Fatal("nil reader accepted")
	}
}

func FuzzJournal(f *testing.F) {
	data, _ := json.Marshal(fixtureJournal(f))
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		j, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		if j.Validate() != nil {
			t.Fatal("invalid decoded journal")
		}
		encoded, err := json.Marshal(j)
		if err != nil {
			t.Fatal(err)
		}
		next, err := Decode(bytes.NewReader(encoded))
		if err != nil || next != j {
			t.Fatal("unstable journal")
		}
	})
}
