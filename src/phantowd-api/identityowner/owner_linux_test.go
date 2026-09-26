// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

type model struct {
	groups, users map[string]serviceaccounts.Account
	calls         int
	fail          bool
	onCommand     func()
}
type modeledBackend struct {
	model   *model
	account serviceaccounts.Account
}

func (b *modeledBackend) Observe(ctx context.Context) (unixidentity.Snapshot, error) {
	return b.model.observe(ctx)
}
func (b *modeledBackend) CreateGroup(_ context.Context, a serviceaccounts.Account) error {
	if a != b.account {
		return errors.New("unexpected modeled account")
	}
	b.model.calls++
	b.model.groups[a.ID] = a
	if b.model.onCommand != nil {
		b.model.onCommand()
	}
	if b.model.fail {
		return errors.New("PRIVATE native command failure")
	}
	return nil
}
func (b *modeledBackend) CreateUser(_ context.Context, a serviceaccounts.Account) error {
	if a != b.account {
		return errors.New("unexpected modeled account")
	}
	b.model.calls++
	b.model.users[a.ID] = a
	return nil
}
func (*modeledBackend) Close() error { return nil }
func (m *model) observe(context.Context) (unixidentity.Snapshot, error) {
	p, g := "root:x:0:0::/:/bin/sh\n", "root:x:0:\n"
	for _, a := range m.groups {
		g += fmt.Sprintf("%s:x:%d:\n", a.Name, a.GID)
	}
	for _, a := range m.users {
		p += fmt.Sprintf("%s:x:%d:%d::/:/sbin/nologin\n", a.Name, a.UID, a.GID)
	}
	return unixidentity.Parse(strings.NewReader(p), strings.NewReader(g))
}
func (m *model) dependencies() dependencies {
	return dependencies{observe: m.observe, executor: func(a serviceaccounts.Account) (backend, error) { return &modeledBackend{m, a}, nil },
		inventory: func(context.Context) (serviceaccounts.Reservations, error) {
			return serviceaccounts.Reservations{UIDs: []uint32{21000}, GIDs: []uint32{21001}, Names: []string{"offlineuser"}}, nil
		}}
}
func newModel() *model {
	return &model{groups: map[string]serviceaccounts.Account{}, users: map[string]serviceaccounts.Account{}}
}
func provision(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("root authority test runs only in isolated container")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{dir + "/registry", dir + "/operations"} {
		if err := os.Mkdir(path, 0700); err != nil {
			t.Fatal(err)
		}
	}
	r, err := serviceaccountstore.Open(dir + "/registry")
	if err != nil {
		t.Fatal(err)
	}
	if err := r.Initialize(21000, 21010); err != nil {
		t.Fatal(err)
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	return dir
}
func fixture(t *testing.T) (*Owner, *model, string) {
	t.Helper()
	dir, m := provision(t), newModel()
	o, err := open(dir, m.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o, m, dir
}

func TestOwnerLifecycleAndExclusiveStores(t *testing.T) {
	o, m, dir := fixture(t)
	ctx := context.Background()
	if competing, err := open(dir, m.dependencies()); !errors.Is(err, ErrBusy) || competing != nil {
		t.Fatal("second owner accepted", err)
	}
	if registry, err := serviceaccountstore.Open(dir + "/registry"); !errors.Is(err, revisionstore.ErrBusy) || registry != nil {
		t.Fatal("registry writer bypassed", err)
	}
	a, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil || a.UID != 21002 {
		t.Fatal(a, err)
	}
	if journal, err := identityprovision.Open(dir + "/operations/first"); !errors.Is(err, revisionstore.ErrBusy) || journal != nil {
		t.Fatal("journal writer bypassed", err)
	}
	if _, err := o.Reserve(ctx, 2, "second", "seconduser"); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	op := o.Operation(a.ID)
	if err := op.Step(ctx, 2); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := op.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Reserve(ctx, 2, "second", "seconduser"); !errors.Is(err, ErrPending) {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = open(dir, m.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	op = o.Operation(a.ID)
	if j, err := op.Load(ctx); err != nil || j.Phase != identityprovision.GroupConfirmed {
		t.Fatal(j, err)
	}
	if err := op.Step(ctx, 3); err != nil {
		t.Fatal(err)
	}
	if err := op.Step(ctx, 3); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if _, err := o.Reserve(ctx, 1, "second", "seconduser"); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	second, err := o.Reserve(ctx, 2, "second", "seconduser")
	if err != nil || second.UID != 21003 {
		t.Fatal(second, err)
	}
	if err := op.Step(ctx, 5); !errors.Is(err, ErrConflict) {
		t.Fatal("old registry revision dispatched", err)
	}
	if j, err := op.Load(ctx); err != nil || j.Revision != 5 {
		t.Fatal(j, err)
	}
	if m.calls != 2 {
		t.Fatal("unexpected commands", m.calls)
	}
	r, journals, err := o.Snapshot(ctx)
	if err != nil || r.Revision != 3 || len(journals) != 2 {
		t.Fatal(r, journals, err)
	}
	r.Accounts[0].Name = "changed"
	if r, _, err := o.Snapshot(ctx); err != nil || r.Accounts[0].Name != a.Name {
		t.Fatal("snapshot aliased live authority")
	}
	for _, revision := range []uint64{1, 3} {
		if err := o.Operation(second.ID).Step(ctx, revision); err != nil {
			t.Fatal(err)
		}
	}
	if m.calls != 4 {
		t.Fatal("second account sequence", m.calls)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	o, err = open(dir, m.dependencies())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if _, journals, err := o.Snapshot(ctx); err != nil || len(journals) != 2 || journals[0].Phase != identityprovision.UnixConfirmed || journals[1].Phase != identityprovision.UnixConfirmed {
		t.Fatal(journals, err)
	}
}

func TestReplacedJournalDirectoryQuarantinesOwner(t *testing.T) {
	o, _, dir := fixture(t)
	ctx := context.Background()
	if _, err := o.Reserve(ctx, 1, "first", "firstuser"); err != nil {
		t.Fatal(err)
	}
	path := dir + "/operations/first"
	if err := os.Rename(path, dir+"/moved-first"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Snapshot(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("replaced journal accepted", err)
	}
	// Restore only this test's exact empty replacement; the live object remains
	// quarantined even when an operator restores the original directory.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(dir+"/moved-first", path); err != nil {
		t.Fatal(err)
	}
	if _, _, err := o.Snapshot(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("quarantine cleared implicitly", err)
	}
}

func TestReservationRefusalAndQuarantine(t *testing.T) {
	o, m, dir := fixture(t)
	ctx := context.Background()
	for _, pair := range [][2]string{{"../escape", "valid"}, {"valid", "offlineuser"}, {"valid", "root"}} {
		if _, err := o.Reserve(ctx, 1, pair[0], pair[1]); err == nil {
			t.Fatal(pair)
		}
	}
	if _, _, err := o.Snapshot(ctx); err != nil {
		t.Fatal("invalid request damaged state", err)
	}
	if err := os.Mkdir(dir+"/registry/.service-accounts.pending", 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Reserve(ctx, 1, "first", "firstuser"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if m.calls != 0 {
		t.Fatal("reservation dispatched native command")
	}
	if _, _, err := o.Snapshot(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatal("quarantine bypassed")
	}
	o.Close()
	if other, err := open(dir, m.dependencies()); err == nil || other != nil {
		t.Fatal("orphan silently recovered")
	}
	data, err := os.ReadFile(dir + "/operations/first/identity-operation.json")
	if err != nil {
		t.Fatal("intent evidence discarded", err)
	}
	if j, err := identityprovision.Decode(strings.NewReader(string(data))); err != nil || j.Phase != identityprovision.Reserved {
		t.Fatal(j, err)
	}
}

func TestReviewAndCooperativeConcurrency(t *testing.T) {
	o, m, _ := fixture(t)
	ctx := context.Background()
	if _, err := o.Reserve(ctx, 1, "first", "firstuser"); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	m.onCommand = func() { close(entered); <-release }
	m.fail = true
	done := make(chan error, 1)
	go func() { done <- o.Operation("first").Step(ctx, 1) }()
	<-entered
	if _, _, err := o.Snapshot(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := o.Reserve(ctx, 2, "other", "otheruser"); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	close(release)
	if err := <-done; !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	if j, err := o.Operation("first").Load(ctx); err != nil || j.Phase != identityprovision.ReviewRequired {
		t.Fatal(j, err)
	}
	if _, err := o.Reserve(ctx, 2, "other", "otheruser"); !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	if err := o.Operation("first").Step(ctx, 3); !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	if m.calls != 1 {
		t.Fatal("review required command repeated")
	}
}

func TestPrivateStorageAndCancellation(t *testing.T) {
	o, m, dir := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.Reserve(ctx, 1, "first", "firstuser"); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if _, err := o.Operation("../outside").Load(context.Background()); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	o.Close()
	if _, err := o.Operation("first").Load(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal(err)
	}
	if err := (&Owner{}).Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if bad, err := open(dir, m.dependencies()); err == nil || bad != nil {
		t.Fatal("permissive owner directory accepted")
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(filepath.Dir(dir), "authority-link")
	if err := os.Symlink(dir, alias); err != nil {
		t.Fatal(err)
	}
	if bad, err := open(alias, m.dependencies()); err == nil || bad != nil {
		t.Fatal("symlink accepted")
	}
}

func TestProcessExitBetweenJournalAndLedger(t *testing.T) {
	if dir := os.Getenv("PHANTOWD_OWNER_CRASH_DIR"); dir != "" {
		m := newModel()
		deps := m.dependencies()
		deps.afterJournal = func() { os.Exit(39) }
		o, err := open(dir, deps)
		if err != nil {
			os.Exit(41)
		}
		_, _ = o.Reserve(context.Background(), 1, "interrupted", "interrupteduser")
		os.Exit(42)
	}
	dir, m := provision(t), newModel()
	cmd := exec.Command(os.Args[0], "-test.run=^TestProcessExitBetweenJournalAndLedger$")
	cmd.Env = append(os.Environ(), "PHANTOWD_OWNER_CRASH_DIR="+dir)
	err := cmd.Run()
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ExitCode() != 39 {
		t.Fatal("wrong interruption boundary", err)
	}
	registry, err := serviceaccountstore.Open(dir + "/registry")
	if err != nil {
		t.Fatal(err)
	}
	r, err := registry.Load()
	registry.Close()
	if err != nil || r.Revision != 1 || len(r.Accounts) != 0 {
		t.Fatal("registry unexpectedly published", r, err)
	}
	if recovered, err := open(dir, m.dependencies()); err == nil || recovered != nil {
		t.Fatal("orphan authorized reuse")
	}
	if _, err := os.Stat(dir + "/operations/interrupted/identity-operation.json"); err != nil {
		t.Fatal("journal evidence lost", err)
	}
}
