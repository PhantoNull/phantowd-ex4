// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
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

type modeledSMB struct {
	observation     smbprovision.Observation
	observeCalls    int
	observeSetCalls int
	observeErr      bool
	createCalls     int
	setCalls        int
	enableCalls     int
	disableCalls    int
	enableErr       bool
	secret          []byte
	onCreate        func()
}

type closeCountingSMB struct {
	modeledSMB
	closeCalls int
}

func (b *closeCountingSMB) Close() error {
	b.closeCalls++
	return nil
}

func (b *modeledSMB) Observe(_ context.Context, account serviceaccounts.Account) (smbprovision.Observation, error) {
	b.observeCalls++
	if b.observeErr {
		return smbprovision.Observation{}, errors.New("PRIVATE SMB observation failure")
	}
	if b.observation.Present && (b.observation.Name != account.Name || b.observation.UID != account.UID || b.observation.GID != account.GID) {
		return smbprovision.Observation{}, errors.New("PRIVATE SMB account mismatch")
	}
	return b.observation, nil
}
func (b *modeledSMB) ObserveAccounts(_ context.Context, accounts []serviceaccounts.Account) ([]smbprovision.Observation, error) {
	b.observeSetCalls++
	if b.observeErr {
		return nil, errors.New("PRIVATE SMB observation failure")
	}
	observations := make([]smbprovision.Observation, len(accounts))
	for i, account := range accounts {
		if b.observation.Present && (b.observation.Name != account.Name || b.observation.UID != account.UID || b.observation.GID != account.GID) {
			return nil, errors.New("PRIVATE SMB account mismatch")
		}
		observations[i] = b.observation
	}
	return observations, nil
}
func (b *modeledSMB) CreateDisabled(_ context.Context, account serviceaccounts.Account) error {
	b.createCalls++
	if b.onCreate != nil {
		b.onCreate()
	}
	b.observation = smbprovision.Observation{Present: true, Name: account.Name, UID: account.UID,
		GID: account.GID, SID: "S-1-5-21-1-2-3-1001", Disabled: true}
	return nil
}
func (b *modeledSMB) SetPasswordDisabled(_ context.Context, account serviceaccounts.Account, secret []byte) error {
	b.setCalls++
	if !b.observation.Present || !b.observation.Disabled || b.observation.Name != account.Name {
		return errors.New("PRIVATE SMB account not disabled")
	}
	b.secret = append([]byte(nil), secret...)
	return nil
}
func (b *modeledSMB) Enable(_ context.Context, account serviceaccounts.Account) error {
	b.enableCalls++
	if !b.observation.Present || !b.observation.Disabled || b.observation.Name != account.Name ||
		b.observation.UID != account.UID || b.observation.GID != account.GID {
		return errors.New("PRIVATE SMB account not disabled")
	}
	if b.enableErr {
		return errors.New("PRIVATE ambiguous SMB enable result")
	}
	b.observation.Disabled = false
	return nil
}
func (b *modeledSMB) Disable(_ context.Context, account serviceaccounts.Account) error {
	b.disableCalls++
	if !b.observation.Present || b.observation.Disabled || b.observation.Name != account.Name ||
		b.observation.UID != account.UID || b.observation.GID != account.GID {
		return errors.New("PRIVATE SMB account not enabled")
	}
	b.observation.Disabled = true
	return nil
}

func completeUnixIdentity(t *testing.T, o *Owner, id string) {
	t.Helper()
	ctx := context.Background()
	if err := o.Operation(id).Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := o.Operation(id).Step(ctx, 3); err != nil {
		t.Fatal(err)
	}
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
	return fixtureWithSMB(t, nil)
}

func fixtureWithSMB(t *testing.T, smbBackend smbprovision.Backend) (*Owner, *model, string) {
	t.Helper()
	dir, m := provision(t), newModel()
	deps := m.dependencies()
	deps.smbBackend = smbBackend
	o, err := open(dir, deps)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { o.Close() })
	return o, m, dir
}

func TestOpenWithSMBBackendTransfersAndClosesOwnershipExactlyOnce(t *testing.T) {
	if os.Getuid() != 0 {
		t.Skip("root authority test runs only in isolated container")
	}
	inventory := Inventory(func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	})

	failedBackend := &closeCountingSMB{}
	invalidDirectory := t.TempDir()
	if err := os.Chmod(invalidDirectory, 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenWithSMBBackend(invalidDirectory, inventory, failedBackend); err == nil || failedBackend.closeCalls != 1 {
		t.Fatalf("failed open must close the transferred backend exactly once: closes=%d error=%v", failedBackend.closeCalls, err)
	}

	backend := &closeCountingSMB{}
	owner, err := OpenWithSMBBackend(provision(t), inventory, backend)
	if err != nil {
		t.Fatal("open owner with bound SMB backend:", err)
	}
	if owner.smbBackend != backend || owner.deps.smbBackend != backend {
		t.Fatal("Owner did not retain the one startup-bound SMB backend")
	}
	if err := owner.Close(); err != nil {
		t.Fatal("close owner:", err)
	}
	if backend.closeCalls != 1 || owner.smbBackend != nil || owner.deps.smbBackend != nil {
		t.Fatalf("owner did not release the backend once: closes=%d owner=%p deps=%p", backend.closeCalls, owner.smbBackend, owner.deps.smbBackend)
	}
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

func TestOwnerDesiredStateTransitionsAreRevisionedAndKeepNativeIdentityImmutable(t *testing.T) {
	o, model, dir := fixture(t)
	ctx := context.Background()
	first, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	if err := o.SetDesiredState(ctx, 2, first.ID, serviceaccounts.Enabled); !errors.Is(err, ErrPending) {
		t.Fatal("desired state changed during incomplete native creation", err)
	}
	completeUnixIdentity(t, o, first.ID)
	if err := o.SetDesiredState(ctx, 2, first.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal("enable desired state", err)
	}

	second, err := o.Reserve(ctx, 3, "second", "seconduser")
	if err != nil {
		t.Fatal("reserve after desired-state revision", err)
	}
	if err := o.SetDesiredState(ctx, 4, first.ID, serviceaccounts.Disabled); !errors.Is(err, ErrPending) {
		t.Fatal("desired state changed while another native creation was pending", err)
	}
	completeUnixIdentity(t, o, second.ID)
	if err := o.SetDesiredState(ctx, 4, first.ID, serviceaccounts.Disabled); err != nil {
		t.Fatal("disable first desired state", err)
	}
	if err := o.SetDesiredState(ctx, 5, second.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal("enable second desired state", err)
	}

	registry, journals, err := o.Snapshot(ctx)
	if err != nil || registry.Revision != 6 || len(registry.Accounts) != 2 || len(journals) != 2 {
		t.Fatal("owner did not preserve revisioned desired state", registry, journals, err)
	}
	if registry.Accounts[0].State != serviceaccounts.Disabled || registry.Accounts[1].State != serviceaccounts.Enabled ||
		journals[0].Account.State != serviceaccounts.Disabled || journals[1].Account.State != serviceaccounts.Disabled ||
		journals[0].RegistryRevision != 2 || journals[1].RegistryRevision != 4 {
		t.Fatal("desired state rewrote immutable native journals or lost creation revisions", registry, journals)
	}
	if model.calls != 4 {
		t.Fatalf("desired-state updates dispatched native commands: calls=%d", model.calls)
	}
	if store, err := serviceaccountstore.Open(dir + "/registry"); !errors.Is(err, revisionstore.ErrBusy) || store != nil {
		t.Fatal("separate registry writer bypassed the Owner lease", store, err)
	}
	if err := o.SetDesiredState(ctx, 4, first.ID, serviceaccounts.Enabled); !errors.Is(err, ErrConflict) {
		t.Fatal("stale desired-state revision was accepted", err)
	}
	if err := o.SetDesiredState(ctx, 6, first.ID, serviceaccounts.Retired); !errors.Is(err, serviceaccounts.ErrTransition) {
		t.Fatal("unsupported retirement was accepted", err)
	}
}

func TestFileServiceSnapshotCollectsReadOnlyIdentityEvidence(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal("reserve account:", err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SetDesiredState(ctx, 2, account.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal("set desired account state:", err)
	}
	smb := o.SMB(account.ID)
	if err := smb.Begin(ctx, 5); err != nil {
		t.Fatal("begin Samba enrollment:", err)
	}
	if err := smb.Step(ctx, 1); err != nil {
		t.Fatal("create disabled Samba entry:", err)
	}
	if err := smb.SetPasswordDisabled(ctx, 3, []byte("test-only-private-secret")); err != nil {
		t.Fatal("set disabled Samba credential:", err)
	}
	if err := smb.Enable(ctx, 5); err != nil {
		t.Fatal("explicitly enable Samba entry:", err)
	}

	mutations := [4]int{backend.createCalls, backend.setCalls, backend.enableCalls, backend.disableCalls}
	first, err := o.FileServiceSnapshot(ctx)
	if err != nil {
		t.Fatal("read file-service identity snapshot:", err)
	}
	if first.Registry.Revision != 3 || len(first.Registry.Accounts) != 1 ||
		first.Registry.Accounts[0].State != serviceaccounts.Enabled || len(first.Native) != 1 ||
		first.Native[0].Phase != identityprovision.UnixConfirmed || len(first.UIDs) != 2 ||
		len(first.GIDs) != 2 || len(first.Samba) != 1 || len(first.Passdb) != 1 ||
		first.Passdb[0].AccountID != account.ID || first.Samba[0].Journal.Phase != smbprovision.Enabled ||
		!first.Samba[0].Observation.Present || first.Samba[0].Observation.Disabled ||
		first.Samba[0].Observation.SID != first.Samba[0].Journal.SID || first.Fingerprint == ([32]byte{}) {
		t.Fatalf("snapshot omitted or misrepresented trusted identity evidence: %+v", first)
	}
	second, err := o.FileServiceSnapshot(ctx)
	if err != nil || first.Fingerprint != second.Fingerprint {
		t.Fatalf("unchanged evidence did not produce a stable fingerprint: first=%x second=%x err=%v", first.Fingerprint, second.Fingerprint, err)
	}
	if backend.observeSetCalls != 2 || [4]int{backend.createCalls, backend.setCalls, backend.enableCalls, backend.disableCalls} != mutations {
		t.Fatalf("snapshot did not use one batched read-only observation or caused a Samba mutation: batch=%d mutations=%v", backend.observeSetCalls, [4]int{backend.createCalls, backend.setCalls, backend.enableCalls, backend.disableCalls})
	}
	if _, err := json.Marshal(first); err == nil {
		t.Fatal("host identity evidence must not be serializable")
	}
	var decoded FileServiceSnapshot
	if err := json.Unmarshal([]byte(`{"registry":{"revision":1}}`), &decoded); err == nil {
		t.Fatal("host identity evidence must not be deserializable")
	}
	backend.observeErr = true
	if _, err := o.FileServiceSnapshot(ctx); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("failed batch observation must refuse the entire snapshot: %v", err)
	}
	backend.observeErr = false

	if err := o.SetDesiredState(ctx, 3, account.ID, serviceaccounts.Disabled); err != nil {
		t.Fatal("change desired state for fingerprint check:", err)
	}
	third, err := o.FileServiceSnapshot(ctx)
	if err != nil || third.Fingerprint == first.Fingerprint {
		t.Fatalf("changed identity state did not change evidence fingerprint: first=%x third=%x err=%v", first.Fingerprint, third.Fingerprint, err)
	}
	first.Registry.Accounts[0].Name = "caller-mutated-copy"
	if latest, err := o.FileServiceSnapshot(ctx); err != nil || latest.Registry.Accounts[0].Name != account.Name {
		t.Fatalf("caller mutation altered Owner state: latest=%+v err=%v", latest, err)
	}
}

func TestFileServiceSnapshotRefusesInterruptedSMBIntentWithoutRecovery(t *testing.T) {
	backend := &modeledSMB{}
	o, _, directory := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal("reserve account:", err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal("begin SMB journal:", err)
	}

	// Model process interruption exactly after a durable command-intent write.
	// This fixture replacement is test-only; production reads never open or
	// initialize a store they did not already own.
	storePath := filepath.Join(directory, "operations", account.ID, "smb")
	store := o.smbJournals[account.ID]
	if err := store.Close(); err != nil {
		t.Fatal("close fixture SMB store:", err)
	}
	intent := smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 2,
		NativeRevision: 5, Account: account, Phase: smbprovision.CreateIntent}
	data, err := json.Marshal(intent)
	if err != nil {
		t.Fatal("encode fixture intent:", err)
	}
	journalPath := filepath.Join(storePath, "smb-operation.json")
	if err := os.WriteFile(journalPath, data, 0600); err != nil {
		t.Fatal("write fixture intent:", err)
	}
	reopened, err := smbprovision.Open(storePath, nil)
	if err != nil {
		t.Fatal("open fixture intent read-only store:", err)
	}
	o.smbJournals[account.ID] = reopened

	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal("read fixture intent before evidence collection:", err)
	}
	mutations := [4]int{backend.createCalls, backend.setCalls, backend.enableCalls, backend.disableCalls}
	if _, err := o.FileServiceSnapshot(ctx); !errors.Is(err, ErrReview) {
		t.Fatalf("interrupted intent must be surfaced for review: %v", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("read-only snapshot changed interrupted intent: before=%s after=%s error=%v", before, after, err)
	}
	if [4]int{backend.createCalls, backend.setCalls, backend.enableCalls, backend.disableCalls} != mutations {
		t.Fatal("read-only snapshot invoked a Samba mutation")
	}
	if backend.observeSetCalls != 0 {
		t.Fatal("uncertain SMB intent reached the passdb observer")
	}
}

func TestFileServiceSnapshotFailsClosedOnReviewRequiredSMBJournal(t *testing.T) {
	backend := &modeledSMB{}
	o, _, directory := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal("reserve account:", err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal("begin Samba journal:", err)
	}

	const sid = "S-1-5-21-1-2-3-1001"
	backend.observation = smbprovision.Observation{Present: true, Name: account.Name,
		UID: account.UID, GID: account.GID, SID: sid, Disabled: false}
	storePath := filepath.Join(directory, "operations", account.ID, "smb")
	if err := o.smbJournals[account.ID].Close(); err != nil {
		t.Fatal("close fixture Samba store:", err)
	}
	review := smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 9,
		NativeRevision: 5, Account: account, SID: sid, Phase: smbprovision.ReviewRequired}
	data, err := json.Marshal(review)
	if err != nil {
		t.Fatal("encode review-required fixture:", err)
	}
	journalPath := filepath.Join(storePath, "smb-operation.json")
	if err := os.WriteFile(journalPath, data, 0600); err != nil {
		t.Fatal("write review-required fixture:", err)
	}
	reopened, err := smbprovision.Open(storePath, nil)
	if err != nil {
		t.Fatal("reopen review-required store:", err)
	}
	o.smbJournals[account.ID] = reopened
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal("read review-required journal before observation:", err)
	}

	if _, err := o.FileServiceSnapshot(ctx); !errors.Is(err, ErrReview) {
		t.Fatalf("review-required identity must refuse the complete evidence snapshot: %v", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("read-only snapshot changed review-required journal: before=%s after=%s error=%v", before, after, err)
	}
	if backend.observeSetCalls != 0 || backend.createCalls != 0 || backend.setCalls != 0 || backend.enableCalls != 0 || backend.disableCalls != 0 {
		t.Fatal("review-required snapshot performed a passdb query or Samba mutation")
	}
}

func TestFileServiceSnapshotRefusesNativeIntentWithoutRecovery(t *testing.T) {
	backend := &modeledSMB{}
	o, _, directory := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal("reserve account:", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal("close fixture Owner before interruption:", err)
	}

	// Model a process exit after the native command intent was durably written.
	// Opening the Owner may read this state, but the evidence-only operation
	// must neither advance it to review nor retry the native command.
	intent := identityprovision.Journal{Format: identityprovision.Format, SchemaVersion: 1,
		Revision: 2, RegistryRevision: 2, Account: account, Phase: identityprovision.GroupIntent}
	data, err := json.Marshal(intent)
	if err != nil {
		t.Fatal("encode native intent fixture:", err)
	}
	journalPath := filepath.Join(directory, "operations", account.ID, "identity-operation.json")
	if err := os.WriteFile(journalPath, data, 0600); err != nil {
		t.Fatal("write native intent fixture:", err)
	}
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal("read native intent before evidence collection:", err)
	}

	model := newModel()
	deps := model.dependencies()
	deps.smbBackend = backend
	reopened, err := open(directory, deps)
	if err != nil {
		t.Fatal("reopen Owner with native intent:", err)
	}
	defer reopened.Close()
	if _, err := reopened.FileServiceSnapshot(ctx); !errors.Is(err, ErrPending) {
		t.Fatalf("native intent must be reported as pending, not recovered: %v", err)
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || string(after) != string(before) {
		t.Fatalf("read-only snapshot changed native intent: before=%s after=%s error=%v", before, after, err)
	}
	if backend.observeSetCalls != 0 {
		t.Fatal("native intent triggered a Samba passdb observation")
	}
}

func TestFileServiceSnapshotUsesOwnerLock(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	defer o.Close()

	o.mu.Lock()
	_, err := o.FileServiceSnapshot(context.Background())
	o.mu.Unlock()
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("file-service evidence bypassed the Owner lock: %v", err)
	}
	if backend.observeSetCalls != 0 {
		t.Fatal("busy Owner still performed a passdb observation")
	}
}

func TestWithFileServiceSnapshotKeepsOwnerLockedDuringInspection(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	defer o.Close()
	ctx := context.Background()
	called := false
	err := o.WithFileServiceSnapshot(ctx, func(snapshot FileServiceSnapshot) error {
		called = true
		if snapshot.Registry.Validate() != nil {
			return errors.New("inspection received invalid Owner snapshot")
		}
		if _, err := o.FileServiceSnapshot(ctx); !errors.Is(err, ErrBusy) {
			return errors.New("nested Owner snapshot did not observe held identity lock")
		}
		return nil
	})
	if err != nil || !called {
		t.Fatalf("Owner inspection did not run under its lock: called=%v err=%v", called, err)
	}
}

func TestFileServiceSnapshotRefusesUnjournaledExistingPassdbIdentity(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal("reserve account:", err)
	}
	completeUnixIdentity(t, o, account.ID)
	backend.observation = smbprovision.Observation{Present: true, Name: account.Name, UID: account.UID,
		GID: account.GID, SID: "S-1-5-21-1-2-3-1001", Disabled: true}
	if _, err := o.FileServiceSnapshot(ctx); !errors.Is(err, ErrReview) {
		t.Fatalf("passdb identity without an Owner journal must require review: %v", err)
	}
	if backend.createCalls != 0 || backend.setCalls != 0 || backend.enableCalls != 0 || backend.disableCalls != 0 {
		t.Fatal("unexpected existing passdb entry triggered a mutation")
	}
}

func TestOwnerDesiredStateRejectsChangedUnixIdentityWithoutMutation(t *testing.T) {
	o, model, _ := fixture(t)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	changed := account
	changed.UID++
	model.users[account.ID] = changed
	if err := o.SetDesiredState(ctx, 2, account.ID, serviceaccounts.Enabled); !errors.Is(err, ErrReview) {
		t.Fatal("desired state changed after Unix identity drift", err)
	}
	registry, journals, err := o.Snapshot(ctx)
	if err != nil || registry.Revision != 2 || len(registry.Accounts) != 1 ||
		registry.Accounts[0].State != serviceaccounts.Disabled || len(journals) != 1 ||
		journals[0].RegistryRevision != 2 || journals[0].Phase != identityprovision.UnixConfirmed || model.calls != 2 {
		t.Fatal("Unix identity mismatch mutated desired/native state", registry, journals, model.calls, err)
	}
}

func TestSMBEnrollmentRequiresUnixConfirmationAndRemainsDisabled(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	smb := o.SMB(account.ID)
	if err := smb.Begin(ctx, 5); !errors.Is(err, ErrPending) || backend.createCalls != 0 || backend.setCalls != 0 {
		t.Fatal("Samba enrollment started before native identity confirmation", err, backend)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := smb.Begin(ctx, 4); !errors.Is(err, ErrConflict) {
		t.Fatal("stale native identity revision accepted", err)
	}
	if err := smb.Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if j, err := smb.Load(ctx); err != nil || j.Phase != smbprovision.Reserved || j.NativeRevision != 5 {
		t.Fatal("Samba journal was not bound to the confirmed Unix identity", j, err)
	}
	if err := smb.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if j, err := smb.Load(ctx); err != nil || j.Phase != smbprovision.DisabledNoPassword || j.Revision != 3 || !backend.observation.Disabled {
		t.Fatal("passdb entry was not created disabled", j, err, backend.observation)
	}
	if err := smb.Step(ctx, 3); !errors.Is(err, smbprovision.ErrPending) || backend.createCalls != 1 {
		t.Fatal("disabled account creation was retried", err, backend.createCalls)
	}
	secret := []byte("test-only-private-secret")
	if err := smb.SetPasswordDisabled(ctx, 3, secret); err != nil {
		t.Fatal(err)
	}
	j, err := smb.Load(ctx)
	if err != nil || j.Phase != smbprovision.CredentialSetDisabled || j.Revision != 5 || !backend.observation.Disabled {
		t.Fatal("credential was not set while disabled", j, err, backend.observation)
	}
	if backend.createCalls != 1 || backend.setCalls != 1 || string(backend.secret) != string(secret) {
		t.Fatal("unexpected Samba command sequence", backend)
	}
	if _, err := smb.Load(ctx); err != nil {
		t.Fatal("completed enrollment could not be read", err)
	}
}

func reviewRequiredSMB(t *testing.T) (*Owner, *model, *modeledSMB, serviceaccounts.Account, string) {
	t.Helper()
	backend := &modeledSMB{}
	o, m, dir := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	smb := o.SMB(account.ID)
	if err := smb.Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := smb.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := smb.SetPasswordDisabled(ctx, 3, []byte("test-only-private-secret")); err != nil {
		t.Fatal(err)
	}
	backend.enableErr = true
	if err := smb.Enable(ctx, 5); !errors.Is(err, smbprovision.ErrReview) {
		t.Fatalf("ambiguous enable was not quarantined: %v", err)
	}
	return o, m, backend, account, dir
}

func TestSMBReviewReadsRedactedObservationWithoutMutation(t *testing.T) {
	o, _, backend, account, dir := reviewRequiredSMB(t)
	ctx := context.Background()
	journalPath := filepath.Join(dir, "operations", account.ID, "smb", "smb-operation.json")
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal("read journal before review:", err)
	}
	journal, err := o.smbJournals[account.ID].Load()
	if err != nil || journal.Phase != smbprovision.ReviewRequired {
		t.Fatal("fixture is not in review-required:", journal, err)
	}
	mutators := [4]int{backend.createCalls, backend.setCalls, backend.enableCalls, backend.disableCalls}
	observes := backend.observeCalls
	observed, err := o.SMB(account.ID).Review(ctx)
	if err != nil {
		t.Fatal("read-only review failed:", err)
	}
	if !observed.Present || observed.Name != account.Name || observed.UID != account.UID || observed.GID != account.GID ||
		observed.SID != backend.observation.SID || observed.Disabled != backend.observation.Disabled {
		t.Fatal("review returned an unexpected redacted observation:", observed)
	}
	if backend.observeCalls != observes+1 || mutators != [4]int{backend.createCalls, backend.setCalls, backend.enableCalls, backend.disableCalls} {
		t.Fatal("review did not perform exactly one observation and zero mutations")
	}
	after, err := os.ReadFile(journalPath)
	if err != nil || string(after) != string(before) {
		t.Fatal("review changed its durable journal", err)
	}
	journal, err = o.smbJournals[account.ID].Load()
	if err != nil || journal.Phase != smbprovision.ReviewRequired {
		t.Fatal("review cleared or changed quarantine:", journal, err)
	}
}

func TestSMBReviewRefusesNonReviewStateWithoutObservation(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	observes := backend.observeCalls
	if _, err := o.SMB(account.ID).Review(ctx); !errors.Is(err, smbprovision.ErrConflict) {
		t.Fatal("review was allowed outside review-required:", err)
	}
	if backend.observeCalls != observes {
		t.Fatal("review observed Samba outside review-required")
	}
}

func TestSMBReviewRespectsOwnerLock(t *testing.T) {
	o, _, backend, account, _ := reviewRequiredSMB(t)
	observes := backend.observeCalls
	o.mu.Lock()
	_, err := o.SMB(account.ID).Review(context.Background())
	o.mu.Unlock()
	if !errors.Is(err, ErrBusy) || backend.observeCalls != observes {
		t.Fatal("review bypassed the Owner lock:", err)
	}
}

func TestSMBReviewRefusesReplacedAccountDirectory(t *testing.T) {
	o, _, backend, account, dir := reviewRequiredSMB(t)
	path := filepath.Join(dir, "operations", account.ID)
	moved := filepath.Join(dir, "operations", "moved-account")
	if err := os.Rename(path, moved); err != nil {
		t.Fatal("move original account directory:", err)
	}
	if err := os.Mkdir(path, 0700); err != nil {
		if restoreErr := os.Rename(moved, path); restoreErr != nil {
			t.Fatal("restore original account directory:", restoreErr)
		}
		t.Fatal("create replacement account directory:", err)
	}
	observes := backend.observeCalls
	if _, err := o.SMB(account.ID).Review(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("review accepted a replaced account directory:", err)
	}
	if backend.observeCalls != observes {
		t.Fatal("review observed Samba through a replaced account directory")
	}
	if err := os.Remove(path); err != nil {
		t.Fatal("remove test replacement directory:", err)
	}
	if err := os.Rename(moved, path); err != nil {
		t.Fatal("restore original account directory:", err)
	}
}

func TestSMBReviewRequiresConfirmedUnixIdentity(t *testing.T) {
	o, m, backend, account, _ := reviewRequiredSMB(t)
	delete(m.users, account.ID)
	observes := backend.observeCalls
	if _, err := o.SMB(account.ID).Review(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal("review proceeded after the Unix identity disappeared:", err)
	}
	if backend.observeCalls != observes {
		t.Fatal("review observed Samba after Unix identity verification failed")
	}
}

func TestSMBReviewRedactsBackendFailure(t *testing.T) {
	o, _, backend, account, _ := reviewRequiredSMB(t)
	backend.observeErr = true
	observed, err := o.SMB(account.ID).Review(context.Background())
	if !errors.Is(err, smbprovision.ErrObservation) || strings.Contains(fmt.Sprint(err), "PRIVATE") || observed != (smbprovision.Observation{}) {
		t.Fatal("review leaked a private backend failure:", observed, err)
	}
}

func TestSMBReviewRejectsInvalidRedactedObservation(t *testing.T) {
	o, _, backend, account, _ := reviewRequiredSMB(t)
	backend.observation.SID = "not-a-sid"
	observed, err := o.SMB(account.ID).Review(context.Background())
	if !errors.Is(err, smbprovision.ErrObservation) || observed != (smbprovision.Observation{}) {
		t.Fatal("review returned invalid Samba identity metadata:", observed, err)
	}
}

func TestSMBEnableIsExplicitAndRevalidatesUnixOwner(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	smb := o.SMB(account.ID)
	if err := smb.Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := smb.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := smb.SetPasswordDisabled(ctx, 3, []byte("test-only-private-secret")); err != nil {
		t.Fatal(err)
	}
	if err := smb.Enable(ctx, 4); !errors.Is(err, smbprovision.ErrConflict) || backend.enableCalls != 0 {
		t.Fatal("stale enable revision reached the backend", err, backend.enableCalls)
	}
	if err := smb.Enable(ctx, 5); err != nil {
		t.Fatal("explicit enable failed", err)
	}
	if err := o.SetDesiredState(ctx, 2, account.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal("separate desired-state enable failed", err)
	}
	journal, err := smb.Load(ctx)
	if err != nil || journal.Phase != smbprovision.Enabled || journal.Revision != 7 || journal.SID != "S-1-5-21-1-2-3-1001" ||
		backend.observation.Disabled || backend.enableCalls != 1 {
		t.Fatal("Owner did not confirm explicit enable", journal, err, backend)
	}
	if err := smb.Enable(ctx, 5); !errors.Is(err, smbprovision.ErrConflict) || backend.enableCalls != 1 {
		t.Fatal("confirmed enable could be replayed", err, backend.enableCalls)
	}
}

func TestSMBDisableUsesOwnerBackendAndCanReenable(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	smb := o.SMB(account.ID)
	if err := smb.Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := smb.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := smb.SetPasswordDisabled(ctx, 3, []byte("test-only-private-secret")); err != nil {
		t.Fatal(err)
	}
	if err := smb.Enable(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := o.SetDesiredState(ctx, 2, account.ID, serviceaccounts.Enabled); err != nil {
		t.Fatal("separate desired-state enable failed", err)
	}
	if err := smb.Disable(ctx, 6); !errors.Is(err, smbprovision.ErrConflict) || backend.disableCalls != 0 {
		t.Fatal("stale disable revision reached the Owner backend", err, backend.disableCalls)
	}
	if err := smb.Disable(ctx, 7); err != nil {
		t.Fatal("explicit disable failed through the Owner", err)
	}
	if err := o.SetDesiredState(ctx, 3, account.ID, serviceaccounts.Disabled); err != nil {
		t.Fatal("separate desired-state disable failed", err)
	}
	if err := smb.Enable(ctx, 8); !errors.Is(err, smbprovision.ErrConflict) || backend.enableCalls != 1 {
		t.Fatal("stale re-enable revision reached the Owner backend", err, backend.enableCalls)
	}
	if err := smb.Enable(ctx, 9); err != nil {
		t.Fatal("explicit re-enable failed through the Owner", err)
	}
	journal, err := smb.Load(ctx)
	if err != nil || journal.Phase != smbprovision.Enabled || journal.Revision != 11 ||
		journal.SID != "S-1-5-21-1-2-3-1001" || backend.disableCalls != 1 || backend.enableCalls != 2 || backend.observation.Disabled {
		t.Fatal("Owner did not retain and use its bound backend for the disable/re-enable cycle", journal, err, backend)
	}
}

func TestSMBEnableRefusesChangedUnixIdentityBeforeDispatch(t *testing.T) {
	backend := &modeledSMB{}
	o, model, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	smb := o.SMB(account.ID)
	if err := smb.Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := smb.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := smb.SetPasswordDisabled(ctx, 3, []byte("test-only-private-secret")); err != nil {
		t.Fatal(err)
	}
	delete(model.users, account.ID)
	if err := smb.Enable(ctx, 5); !errors.Is(err, ErrReview) || backend.enableCalls != 0 {
		t.Fatal("enable did not revalidate Unix identity before dispatch", err, backend.enableCalls)
	}
}

func TestSMBEnrollmentFailsClosedWithoutOwnerConfiguredBackend(t *testing.T) {
	o, _, dir := fixture(t)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SMB(account.ID).Begin(ctx, 5); !errors.Is(err, smbprovision.ErrInvalid) {
		t.Fatal("owner without a bound trusted backend accepted enrollment", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "operations", account.ID, "smb")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("missing backend left an enrollment journal directory", err)
	}
}

func TestSMBEnrollmentUsesTheGlobalOwnerLock(t *testing.T) {
	backend := &modeledSMB{}
	o, _, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	entered, release := make(chan struct{}), make(chan struct{})
	backend.onCreate = func() { close(entered); <-release }
	stepDone := make(chan error, 1)
	go func() { stepDone <- o.SMB(account.ID).Step(ctx, 1) }()
	<-entered
	if _, err := o.Operation(account.ID).Load(ctx); !errors.Is(err, ErrBusy) {
		t.Fatal("Unix identity operation bypassed an in-flight Samba mutation", err)
	}
	close(release)
	if err := <-stepDone; err != nil {
		t.Fatal(err)
	}
	if backend.createCalls != 1 {
		t.Fatal("unexpected Samba create count", backend.createCalls)
	}
}

func TestSMBPreexistingPassdbAccountIsRefusedWithoutCreatingJournal(t *testing.T) {
	backend := &modeledSMB{}
	o, _, dir := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	backend.observation = smbprovision.Observation{Present: true, Name: account.Name,
		UID: account.UID, GID: account.GID, SID: "S-1-5-21-1-2-3-1001", Disabled: true}
	if err := o.SMB(account.ID).Begin(ctx, 5); !errors.Is(err, smbprovision.ErrReview) {
		t.Fatal("pre-existing passdb entry was adopted", err)
	}
	if backend.createCalls != 0 || backend.setCalls != 0 {
		t.Fatal("pre-existing passdb entry caused mutation", backend)
	}
	if _, _, err := o.Snapshot(ctx); err != nil {
		t.Fatal("refused existing entry left an orphan journal directory", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "operations", account.ID, "smb")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("empty enrollment directory was not safely removed", err)
	}
}

func TestSMBMutationRefusesChangedUnixIdentity(t *testing.T) {
	backend := &modeledSMB{}
	o, model, _ := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	delete(model.users, account.ID)
	if err := o.SMB(account.ID).Step(ctx, 1); !errors.Is(err, ErrReview) || backend.createCalls != 0 {
		t.Fatal("Samba mutation did not revalidate the live Unix identity", err, backend.createCalls)
	}
	if journal, err := o.SMB(account.ID).Load(ctx); err != nil || journal.Phase != smbprovision.Reserved {
		t.Fatal("pre-command Unix mismatch unexpectedly advanced Samba state", journal, err)
	}
}

func TestHelperSMBIntentExit(t *testing.T) {
	dir := os.Getenv("PHANTOWD_OWNER_SMB_CRASH_DIR")
	if dir == "" {
		return
	}
	m := newModel()
	deps := m.dependencies()
	deps.smbBackend = &exitAfterSMBIntent{}
	o, err := open(dir, deps)
	if err != nil {
		os.Exit(81)
	}
	journal, err := o.Operation("first").Load(context.Background())
	if err != nil {
		os.Exit(82)
	}
	m.groups[journal.Account.ID] = journal.Account
	m.users[journal.Account.ID] = journal.Account
	_ = o.SMB("first").Step(context.Background(), 1)
	os.Exit(83)
}

type exitAfterSMBIntent struct{}

func (*exitAfterSMBIntent) Observe(context.Context, serviceaccounts.Account) (smbprovision.Observation, error) {
	return smbprovision.Observation{}, nil
}
func (*exitAfterSMBIntent) CreateDisabled(context.Context, serviceaccounts.Account) error {
	os.Exit(42)
	return nil
}
func (*exitAfterSMBIntent) SetPasswordDisabled(context.Context, serviceaccounts.Account, []byte) error {
	os.Exit(43)
	return nil
}
func (*exitAfterSMBIntent) Enable(context.Context, serviceaccounts.Account) error {
	os.Exit(44)
	return nil
}
func (*exitAfterSMBIntent) Disable(context.Context, serviceaccounts.Account) error {
	os.Exit(45)
	return nil
}

func TestOwnerReopensInterruptedSMBIntentAsReviewWithoutRetry(t *testing.T) {
	backend := &modeledSMB{}
	o, _, dir := fixtureWithSMB(t, backend)
	ctx := context.Background()
	account, err := o.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, o, account.ID)
	if err := o.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestHelperSMBIntentExit$")
	command.Env = append(os.Environ(), "PHANTOWD_OWNER_SMB_CRASH_DIR="+dir)
	if err := command.Run(); err == nil {
		t.Fatal("child unexpectedly survived the interrupted SMB operation")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 {
		t.Fatal("unexpected interrupted SMB child result", err)
	}
	m := newModel()
	m.groups[account.ID] = account
	m.users[account.ID] = account
	deps := m.dependencies()
	deps.smbBackend = backend
	reopened, err := open(dir, deps)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	journal, err := reopened.SMB(account.ID).Load(ctx)
	if err != nil || journal.Phase != smbprovision.ReviewRequired || journal.Revision != 3 {
		t.Fatal("owner did not durably quarantine the interrupted intent", journal, err)
	}
	if native, err := reopened.Operation(account.ID).Load(ctx); err != nil || native.Phase != identityprovision.UnixConfirmed {
		t.Fatal("Samba recovery changed the Unix identity journal", native, err)
	}
	if err := reopened.SMB(account.ID).Step(ctx, 3); !errors.Is(err, smbprovision.ErrReview) || backend.createCalls != 0 {
		t.Fatal("interrupted Samba command was automatically retried", err, backend.createCalls)
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
