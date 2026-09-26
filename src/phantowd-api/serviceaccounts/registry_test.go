// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package serviceaccounts

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func emptyReservations() Reservations {
	return Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}
}
func initial(t *testing.T) Registry {
	t.Helper()
	r, err := New(20000, 20200)
	if err != nil {
		t.Fatal(err)
	}
	return r
}
func create(t *testing.T, r Registry, id string) Registry {
	t.Helper()
	next, err := r.Create(r.Revision, id, id, emptyReservations())
	if err != nil {
		t.Fatal(err)
	}
	return next
}
func state(t *testing.T, r Registry, id, next string) Registry {
	t.Helper()
	r, err := r.SetState(r.Revision, id, next)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func TestIdentityLifecycle(t *testing.T) {
	r := initial(t)
	reserved := Reservations{UIDs: []uint32{20000}, GIDs: []uint32{20001}, Names: []string{"system"}}
	next, err := r.Create(1, "alice", "alice", reserved)
	if err != nil || next.Revision != 2 || next.Accounts[0].UID != 20002 || next.Accounts[0].GID != 20002 || next.Accounts[0].State != Disabled {
		t.Fatal(next, err)
	}
	if len(r.Accounts) != 0 || r.Revision != 1 {
		t.Fatal("input mutated")
	}
	active := state(t, next, "alice", Enabled)
	if next.Accounts[0].State != Disabled {
		t.Fatal("shared slice")
	}
	if _, err := active.SetState(active.Revision, "alice", Retired); !errors.Is(err, ErrTransition) {
		t.Fatal(err)
	}
	retired := state(t, state(t, active, "alice", Disabled), "alice", Retired)
	for _, target := range []string{Enabled, Disabled, Retired} {
		if _, err := retired.SetState(retired.Revision, "alice", target); !errors.Is(err, ErrTransition) {
			t.Fatal(err)
		}
	}
	for _, pair := range [][2]string{{"alice", "newname"}, {"newid", "alice"}} {
		if _, err := retired.Create(retired.Revision, pair[0], pair[1], reserved); !errors.Is(err, ErrCollision) {
			t.Fatal(err)
		}
	}
	after, err := retired.Create(retired.Revision, "bob", "bob", reserved)
	if err != nil || after.Accounts[1].UID != 20003 || after.Accounts[0] != retired.Accounts[0] {
		t.Fatal(after, err)
	}
	data, _ := json.Marshal(after)
	decoded, err := Decode(bytes.NewReader(data))
	if err != nil || !reflect.DeepEqual(decoded, after) {
		t.Fatal(err)
	}
}

func TestPlannerRefusals(t *testing.T) {
	r := initial(t)
	if _, err := r.Create(0, "alice", "alice", emptyReservations()); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	r.Revision = math.MaxUint64
	if _, err := r.Create(r.Revision, "alice", "alice", emptyReservations()); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	r = initial(t)
	for _, reservation := range []Reservations{{}, {UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{"bad\nname"}}, {UIDs: make([]uint32, 65537), GIDs: []uint32{}, Names: []string{}}} {
		if _, err := r.Create(1, "alice", "alice", reservation); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	reserved := emptyReservations()
	reserved.Names = []string{"ALICE"}
	if _, err := r.Create(1, "alice", "alice", reserved); !errors.Is(err, ErrCollision) {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"bad id", "alice"}, {"alice", "root"}, {"alice", "a:b"}} {
		if _, err := r.Create(1, pair[0], pair[1], emptyReservations()); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	for _, target := range []string{Disabled, "unknown"} {
		created := create(t, r, "alice")
		if _, err := created.SetState(created.Revision, "alice", target); !errors.Is(err, ErrTransition) {
			t.Fatal(err)
		}
	}
	if _, err := r.SetState(1, "missing", Enabled); !errors.Is(err, ErrTransition) {
		t.Fatal(err)
	}
	small, _ := New(1000, 1000)
	small = create(t, small, "one")
	if _, err := small.Create(small.Revision, "two", "two", emptyReservations()); !errors.Is(err, ErrExhausted) {
		t.Fatal(err)
	}
	for _, bounds := range [][2]uint32{{0, 1000}, {999, 1000}, {2000, 1000}, {1000, 60001}, {1000, math.MaxUint32}} {
		if _, err := New(bounds[0], bounds[1]); !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
}

func TestStrictRegistry(t *testing.T) {
	r := create(t, initial(t), "alice")
	data, _ := json.Marshal(r)
	for _, input := range []string{
		string(data) + "{}", strings.Replace(string(data), `"revision":2`, `"revision":2,"revision":3`, 1),
		strings.Replace(string(data), `"revision":2,`, "", 1),
		strings.Replace(string(data), `"accounts":[`, `"password":"secret","accounts":[`, 1),
		strings.Replace(string(data), `"state":"disabled"`, `"state":null`, 1),
		strings.Replace(string(data), `"state":"disabled"`, `"state":"unknown"`, 1),
		strings.Replace(string(data), `"uid":20000`, `"uid":0`, 1),
		strings.Replace(string(data), `"gid":20000`, `"gid":20001`, 1),
		strings.Replace(string(data), `"uid":20000`, `"UID":20000`, 1),
		strings.Repeat(" ", MaxInputBytes+1),
	} {
		if _, err := Decode(strings.NewReader(input)); !errors.Is(err, ErrInvalid) {
			t.Fatal("accepted invalid document", err)
		}
	}
	duplicate := r
	duplicate.Accounts = append([]Account{}, r.Accounts...)
	duplicate.Accounts = append(duplicate.Accounts, r.Accounts[0])
	if duplicate.Validate() == nil {
		t.Fatal("duplicate")
	}
}

func TestCapacityAndMaxDocument(t *testing.T) {
	r, _ := New(1000, 60000)
	for i := 0; i < MaxRecords; i++ {
		r.Accounts = append(r.Accounts, Account{ID: fmt.Sprintf("user-%04d", i), Name: fmt.Sprintf("user%04d", i), UID: uint32(1000 + i), GID: uint32(1000 + i), State: Retired})
	}
	if err := r.Validate(); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Create(1, "new", "new", emptyReservations()); !errors.Is(err, ErrExhausted) {
		t.Fatal(err)
	}
	data, _ := json.Marshal(r)
	if len(data) > MaxInputBytes {
		t.Fatal("schema exceeds input bound")
	}
	if _, err := Decode(bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
	r.Accounts = append(r.Accounts, r.Accounts[0])
	if r.Validate() == nil {
		t.Fatal("too many lifetime records")
	}
	r.Accounts = r.Accounts[:MaxLive]
	for i := range r.Accounts {
		r.Accounts[i].State = Disabled
	}
	if _, err := r.Create(1, "new", "new", emptyReservations()); !errors.Is(err, ErrExhausted) {
		t.Fatal(err)
	}
	r.Accounts = append(r.Accounts, Account{ID: "extra", Name: "extra", UID: 59999, GID: 59999, State: Disabled})
	if r.Validate() == nil {
		t.Fatal("too many live identities")
	}
	if _, err := r.SetState(1, "extra", Enabled); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := r.BindShares(shareconfig.Config{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestBindingRequiresExactEnabledIdentity(t *testing.T) {
	r := create(t, initial(t), "alice")
	p := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 7,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{{ID: "alice", Name: "alice"}, {ID: "unused", Name: "unused"}},
		Shares:  []shareconfig.Share{{ID: "files", Name: "Files", VolumeID: "bulk", RelativePath: "files", Grants: []shareconfig.Grant{{UserID: "alice", Access: "ro"}}}}}
	if _, err := r.BindShares(p); !errors.Is(err, ErrUnresolved) {
		t.Fatal(err)
	}
	r = state(t, r, "alice", Enabled)
	got, err := r.BindShares(p)
	if err != nil || len(got.Accounts) != 1 || got.Accounts[0].UID != 20000 || got.RegistryRevision != r.Revision || got.ShareRevision != 7 {
		t.Fatal(got, err)
	}
	got.Accounts[0].Name = "changed"
	if r.Accounts[0].Name != "alice" {
		t.Fatal("aliased binding")
	}
	p.Users[0].Name = "bob"
	if _, err := r.BindShares(p); !errors.Is(err, ErrUnresolved) {
		t.Fatal(err)
	}
	p.Users[0].Name = "alice"
	p.Users[0].ID = "different"
	p.Shares[0].Grants[0].UserID = "different"
	if _, err := r.BindShares(p); !errors.Is(err, ErrUnresolved) {
		t.Fatal(err)
	}
}

func FuzzRegistry(f *testing.F) {
	r, _ := New(20000, 20200)
	data, _ := json.Marshal(r)
	f.Add(data)
	r, _ = r.Create(1, "alice", "alice", emptyReservations())
	data, _ = json.Marshal(r)
	f.Add(data)
	f.Fuzz(func(t *testing.T, data []byte) {
		decoded, err := Decode(bytes.NewReader(data))
		if err != nil {
			return
		}
		if decoded.Validate() != nil {
			t.Fatal("invalid decoded registry")
		}
		canonical, err := json.Marshal(decoded)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(bytes.NewReader(canonical))
		if err != nil || !reflect.DeepEqual(decoded, again) {
			t.Fatal("round trip")
		}
		next, err := decoded.Create(decoded.Revision, "fuzz-account", "fuzzaccount", emptyReservations())
		if err == nil && (next.Validate() != nil || next.Revision != decoded.Revision+1 || len(next.Accounts) != len(decoded.Accounts)+1 || !reflect.DeepEqual(next.Accounts[:len(decoded.Accounts)], decoded.Accounts)) {
			t.Fatal("allocation invariant")
		}
		if len(decoded.Accounts) > 0 {
			for _, target := range []string{Enabled, Disabled, Retired} {
				next, err := decoded.SetState(decoded.Revision, decoded.Accounts[0].ID, target)
				if err != nil {
					continue
				}
				if next.Validate() != nil || next.Revision != decoded.Revision+1 || len(next.Accounts) != len(decoded.Accounts) {
					t.Fatal("state transition invariant")
				}
				next.Accounts[0].State = decoded.Accounts[0].State
				if !reflect.DeepEqual(next.Accounts, decoded.Accounts) {
					t.Fatal("state transition changed identity")
				}
			}
		}
	})
}

func TestBindingsAreSortedDeduplicatedAndAllOrError(t *testing.T) {
	r := initial(t)
	for _, name := range []string{"zoe", "alice"} {
		r = state(t, create(t, r, name), name, Enabled)
	}
	p := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
		Users:   []shareconfig.User{{ID: "zoe", Name: "zoe"}, {ID: "alice", Name: "alice"}},
		Shares: []shareconfig.Share{
			{ID: "one", Name: "One", VolumeID: "bulk", RelativePath: "one", Grants: []shareconfig.Grant{{UserID: "zoe", Access: "ro"}, {UserID: "alice", Access: "rw"}}},
			{ID: "two", Name: "Two", VolumeID: "bulk", RelativePath: "two", Grants: []shareconfig.Grant{{UserID: "zoe", Access: "rw"}}},
		}}
	got, err := r.BindShares(p)
	if err != nil || len(got.Accounts) != 2 || got.Accounts[0].ID != "alice" || got.Accounts[1].ID != "zoe" {
		t.Fatal(got, err)
	}
	r = state(t, r, "alice", Disabled)
	got, err = r.BindShares(p)
	if !errors.Is(err, ErrUnresolved) || !reflect.DeepEqual(got, Bindings{}) {
		t.Fatal("partial binding escaped", got, err)
	}
}
