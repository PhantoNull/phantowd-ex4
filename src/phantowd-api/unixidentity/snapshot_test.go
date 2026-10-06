// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package unixidentity

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

const basePasswd = "root:x:0:0:root:/root:/bin/sh\n"
const baseGroups = "root:x:0:\n"
const accountRow = "alice:x:20000:20000:Private description:/nonexistent:/sbin/nologin\n"
const groupRow = "alice:x:20000:alice\n"

var desired = serviceaccounts.Account{ID: "alice", Name: "alice", UID: 20000, GID: 20000, State: serviceaccounts.Disabled}

func TestAssessIdentityStates(t *testing.T) {
	for _, test := range []struct{ label, passwd, groups, status string }{
		{"absent", "", "", Absent},
		{"group-only", "", groupRow, Partial},
		{"user-only", accountRow, "", Partial},
		{"exact", accountRow, groupRow, Observed},
		{"implicit-primary-member", accountRow, "alice:x:20000:\n", Observed},
		{"wrong-uid", strings.Replace(accountRow, ":20000:", ":20001:", 1), groupRow, Conflict},
		{"wrong-primary-gid", strings.Replace(accountRow, ":20000:20000:", ":20000:20001:", 1), groupRow, Conflict},
		{"group-gid", accountRow, "alice:x:20001:\n", Conflict},
		{"uid-alias", accountRow + "alias:x:20000:1::/:/bin/false\n", groupRow, Conflict},
		{"gid-alias", accountRow, groupRow + "alias:x:20000:\n", Conflict},
		{"other-primary-member", accountRow + "other:x:20001:20000::/:/bin/false\n", groupRow, Conflict},
		{"other-member", accountRow, "alice:x:20000:alice,other\n", Conflict},
		{"supplementary-membership", accountRow, groupRow + "wheel:x:10:alice\n", Conflict},
		{"orphan-membership", "", "wheel:x:10:alice\n", Conflict},
		{"case-user", "ALICE:x:20000:20000::/:/bin/false\n", groupRow, Conflict},
		{"case-group", accountRow, "ALICE:x:20000:\n", Conflict},
	} {
		t.Run(test.label, func(t *testing.T) {
			s, err := Parse(strings.NewReader(basePasswd+test.passwd), strings.NewReader(baseGroups+test.groups))
			if err != nil {
				t.Fatal(err)
			}
			got, err := s.Assess(desired)
			if err != nil || got != test.status {
				t.Fatal(got, err)
			}
		})
	}
}

func TestReservationsAndSecretOmission(t *testing.T) {
	passwd := basePasswd + "existing:secret-passwd-value:20000:20001:Secret GECOS:/secret/home:/secret/shell\n"
	groups := baseGroups + "occupied:secret-group-value:20002:orphan\n"
	s, err := Parse(strings.NewReader(passwd), strings.NewReader(groups))
	if err != nil {
		t.Fatal(err)
	}
	r, err := s.Reservations()
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(r.UIDs, []uint32{0, 20000}) || !reflect.DeepEqual(r.GIDs, []uint32{0, 20001, 20002}) || !slices.Contains(r.Names, "orphan") {
		t.Fatal(r)
	}
	registry, _ := serviceaccounts.New(20000, 20010)
	allocated, err := registry.Create(1, "alice", "alice", r)
	if err != nil || allocated.Accounts[0].UID != 20003 {
		t.Fatal(allocated, err)
	}
	for _, name := range []string{"occupied", "orphan", "existing"} {
		if _, err := registry.Create(1, "new", name, r); !errors.Is(err, serviceaccounts.ErrCollision) {
			t.Fatal(err)
		}
	}
	r.UIDs[0] = 90000
	r.Names[0] = "changed"
	again, _ := s.Reservations()
	if again.UIDs[0] != 0 || slices.Contains(again.Names, "changed") {
		t.Fatal("mutable snapshot")
	}
	encoded, _ := json.Marshal(s)
	if string(encoded) != "{}" || strings.Contains(fmt.Sprintf("%+v", s), "secret") {
		t.Fatal("private fields escaped observation")
	}
}

type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errors.New("sensitive-reader-detail") }

func TestMalformedInputsFailEntireObservation(t *testing.T) {
	for _, input := range []string{"", "# comment only\n", "alice:x:1:1:only-six:/\n", basePasswd + basePasswd,
		"+::::::\n", "alice:x:-1:1::/:/bin/sh\n", "alice:x:1:+1::/:/bin/sh\n", "alice:x:4294967295:1::/:/bin/sh\n",
		"alice:x:4294967296:1::/:/bin/sh\n", "alice:x::1::/:/bin/sh\n", "alice:x:1:99999999999::/:/bin/sh\n",
		"a b:x:1:1::/:/bin/sh\n", basePasswd + "\r", basePasswd + "\x00", basePasswd + "\xff",
		strings.Repeat("#", MaxLineBytes+1), strings.Repeat("\n", MaxFileBytes+1)} {
		s, err := Parse(strings.NewReader(input), strings.NewReader(baseGroups))
		if !errors.Is(err, ErrInvalid) || s.valid {
			t.Fatal("bad passwd accepted", err)
		}
	}
	for _, input := range []string{"", baseGroups + baseGroups, "alice:x:1:alice,alice\n", "alice:x:1:alice,\n", "alice:x:-1:\n", "alice:x:1:bad member\n", "alice:x:1::extra\n"} {
		if _, err := Parse(strings.NewReader(basePasswd), strings.NewReader(input)); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad group", err)
		}
	}
	for _, reader := range []io.Reader{nil, brokenReader{}} {
		if _, err := Parse(reader, strings.NewReader(baseGroups)); !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), "sensitive") {
			t.Fatal(err)
		}
	}
	var zero Snapshot
	if _, err := zero.Reservations(); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := zero.Assess(desired); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	s, _ := Parse(strings.NewReader(basePasswd), strings.NewReader(baseGroups))
	if _, err := s.Assess(serviceaccounts.Account{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	var many strings.Builder
	for i := 0; i <= MaxRecords; i++ {
		fmt.Fprintf(&many, "u%d:x:%d:1::/:/bin/false\n", i, i)
	}
	if _, err := Parse(strings.NewReader(many.String()), strings.NewReader(baseGroups)); !errors.Is(err, ErrInvalid) {
		t.Fatal("record limit", err)
	}
}

func FuzzSnapshot(f *testing.F) {
	f.Add(basePasswd+accountRow, baseGroups+groupRow)
	f.Add(basePasswd, baseGroups)
	f.Fuzz(func(t *testing.T, passwd, groups string) {
		s, err := Parse(strings.NewReader(passwd), strings.NewReader(groups))
		if err != nil {
			return
		}
		status, err := s.Assess(desired)
		if err != nil || status != Absent && status != Partial && status != Conflict && status != Observed {
			t.Fatal("invalid assessment")
		}
		r, err := s.Reservations()
		if err != nil {
			return
		}
		if !slices.IsSorted(r.UIDs) || !slices.IsSorted(r.GIDs) || !slices.IsSorted(r.Names) {
			t.Fatal("nondeterministic exclusions")
		}
		native, _ := serviceaccounts.New(20000, 20010)
		next, err := native.Create(1, "alice", "alice", r)
		if err == nil && next.Validate() != nil {
			t.Fatal("invalid native identity")
		}
		if err == nil {
			status, err := s.Assess(next.Accounts[0])
			if err != nil || status != Absent {
				t.Fatal("new allocation conflicts with local identity")
			}
		}
	})
}
