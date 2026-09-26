// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package serviceaccountstore

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

func reservations() serviceaccounts.Reservations {
	return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}
}
func privateDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestRegistryStoreRetainsIdentityAcrossReopen(t *testing.T) {
	dir := privateDirectory(t)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if _, err := s.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) {
		t.Fatal(err)
	}
	if err := s.Create(0, "alice", "alice", reservations()); !errors.Is(err, revisionstore.ErrNotInitialized) {
		t.Fatal(err)
	}
	if err := s.Initialize(20000, 20010); err != nil {
		t.Fatal(err)
	}
	if err := s.Initialize(20000, 20010); !errors.Is(err, revisionstore.ErrConflict) {
		t.Fatal("reset allowed", err)
	}
	if err := s.Create(1, "alice", "alice", reservations()); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(2, "alice", serviceaccounts.Retired); err != nil {
		t.Fatal(err)
	}
	if err := s.SetState(3, "alice", serviceaccounts.Enabled); !errors.Is(err, serviceaccounts.ErrTransition) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	// A staged revision is never adopted and cannot erase the retired identity.
	pending := []byte(`{"format":"phantowd-service-accounts","schema_version":1,"revision":4,"first_id":20000,"last_id":20010,"accounts":[]}`)
	if err := os.WriteFile(filepath.Join(dir, ".service-accounts.pending"), pending, 0600); err != nil {
		t.Fatal(err)
	}
	s, err = Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.Load()
	if err != nil || r.Revision != 3 || len(r.Accounts) != 1 || r.Accounts[0].State != serviceaccounts.Retired {
		t.Fatal(r, err)
	}
	r.Accounts = nil // The loaded snapshot must not mutate persisted reservations.
	if err := s.Create(3, "new-id", "alice", reservations()); !errors.Is(err, serviceaccounts.ErrCollision) {
		t.Fatal(err)
	}
	if err := s.Create(3, "bob", "bob", reservations()); err != nil {
		t.Fatal(err)
	}
	r, err = s.Load()
	if err != nil || len(r.Accounts) != 2 || r.Accounts[1].UID != 20001 {
		t.Fatal(r, err)
	}
	if err := s.Create(3, "stale", "stale", reservations()); !errors.Is(err, serviceaccounts.ErrConflict) {
		t.Fatal(err)
	}
	if second, err := Open(dir); !errors.Is(err, revisionstore.ErrBusy) {
		if second != nil {
			second.Close()
		}
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
	if err := s.Create(4, "closed", "closed", reservations()); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
	if err := s.Initialize(20000, 20010); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	corrupt := []byte("{truncated")
	if err := os.WriteFile(filepath.Join(dir, "service-accounts.json"), corrupt, 0600); err != nil {
		t.Fatal(err)
	}
	if broken, err := Open(dir); !errors.Is(err, revisionstore.ErrInvalid) {
		if broken != nil {
			broken.Close()
		}
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "service-accounts.json"))
	if err != nil || !bytes.Equal(data, corrupt) {
		t.Fatal("corrupt evidence replaced", err)
	}
}

func TestRegistryConcurrentAllocation(t *testing.T) {
	s, err := Open(privateDirectory(t))
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Initialize(20000, 20010); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, id := range []string{"alice", "bob"} {
		wg.Add(1)
		go func() { defer wg.Done(); results <- s.Create(1, id, id, reservations()) }()
	}
	wg.Wait()
	close(results)
	winners, conflicts := 0, 0
	for err := range results {
		if err == nil {
			winners++
		} else if errors.Is(err, serviceaccounts.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if winners != 1 || conflicts != 1 {
		t.Fatal(winners, conflicts)
	}
	r, err := s.Load()
	if err != nil || r.Revision != 2 || len(r.Accounts) != 1 {
		t.Fatal(r, err)
	}
}

func TestRegistryStorageRefusals(t *testing.T) {
	dir := privateDirectory(t)
	if _, err := Open(filepath.Join(dir, "absent")); !errors.Is(err, revisionstore.ErrUnsafe) {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Initialize(0, 1000); !errors.Is(err, serviceaccounts.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := s.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) {
		t.Fatal(err)
	}
	var zero Store
	if _, err := zero.Load(); !errors.Is(err, revisionstore.ErrClosed) {
		t.Fatal(err)
	}
}
