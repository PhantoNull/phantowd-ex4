// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package identityowner owns a native reservation ledger and its creation
// journals under one cooperative lifetime lease. It does not provision storage.
package identityowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
	"golang.org/x/sys/unix"
)

var (
	ErrUnavailable = errors.New("native identity authority unavailable or requires recovery")
	ErrBusy        = errors.New("native identity authority is busy")
	ErrPending     = errors.New("native identity creation is incomplete")
	ErrConflict    = identityprovision.ErrConflict
	ErrReview      = identityprovision.ErrReview
	ErrInvalid     = identityprovision.ErrInvalid
)

// Inventory is trusted caller-owned discovery, never a request field. It must
// supply COMPLETE external/offline/imported identity reservations on every call
// and fail if completeness cannot be established. Local /etc exclusions are
// independently added by this owner. Empty slices are an explicit assertion.
type Inventory func(context.Context) (serviceaccounts.Reservations, error)

type backend interface {
	identityprovision.Backend
	Close() error
}
type dependencies struct {
	observe      func(context.Context) (unixidentity.Snapshot, error)
	executor     func(serviceaccounts.Account) (backend, error)
	inventory    Inventory
	smbBackend   smbprovision.Backend
	afterJournal func() // private process-interruption test seam
}

type Owner struct {
	mu                    sync.Mutex
	root, operations      int
	device                uint64
	registry              *serviceaccountstore.Store
	journals              map[string]*identityprovision.Store
	smbJournals           map[string]*smbprovision.Store
	smbBackend            smbprovision.Backend
	inodes                map[string]uint64
	smbInodes             map[string]uint64
	deps                  dependencies
	failed, closed, ready bool
}

// Open requires pre-provisioned root-owned 0700 root/registry/operations
// directories on one local filesystem and an explicitly initialized empty or
// previously owner-managed registry. It never bootstraps, imports or repairs.
func Open(directory string, inventory Inventory) (*Owner, error) {
	return open(directory, ownerDependencies(inventory))
}

// OpenWithSMBBackend binds a trusted in-process Samba executor to the Owner for
// its lifetime. Pass only a fixed implementation created by the firmware
// service, never a per-request adapter; client protocols cannot configure it.
// This transfers ownership: if opening fails, a closeable backend is closed;
// otherwise Owner.Close closes it after draining active operations.
// The internal package type intentionally keeps this constructor inside the
// phantowd-api module subtree.
func OpenWithSMBBackend(directory string, inventory Inventory, smbBackend smbprovision.Backend) (*Owner, error) {
	if smbBackend == nil {
		return nil, ErrInvalid
	}
	deps := ownerDependencies(inventory)
	deps.smbBackend = smbBackend
	return open(directory, deps)
}

func ownerDependencies(inventory Inventory) dependencies {
	return dependencies{
		inventory: inventory,
		observe: func(ctx context.Context) (unixidentity.Snapshot, error) {
			if err := ctx.Err(); err != nil {
				return unixidentity.Snapshot{}, err
			}
			return unixidentity.ReadLocal("/etc", 0)
		},
		executor: func(a serviceaccounts.Account) (backend, error) { return identityexec.Open(a) },
	}
}

func open(directory string, deps dependencies) (*Owner, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || deps.inventory == nil || deps.observe == nil || deps.executor == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		closeSMBBackend(deps.smbBackend)
		return nil, ErrInvalid
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		closeSMBBackend(deps.smbBackend)
		return nil, ErrUnavailable
	}
	o := &Owner{root: fd, operations: -1, deps: deps, smbBackend: deps.smbBackend,
		journals: make(map[string]*identityprovision.Store), smbJournals: make(map[string]*smbprovision.Store),
		inodes: make(map[string]uint64), smbInodes: make(map[string]uint64), ready: true}
	success := false
	defer func() {
		if !success {
			o.Close()
		}
	}()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || !privateDirectory(st) {
		return nil, ErrUnavailable
	}
	o.device = uint64(st.Dev)
	if err := unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return nil, ErrBusy
		}
		return nil, ErrUnavailable
	}
	for _, name := range []string{"registry", "operations"} {
		if unix.Fstatat(fd, name, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !privateDirectory(st) || uint64(st.Dev) != o.device {
			return nil, ErrUnavailable
		}
	}
	o.operations, err = unix.Openat(fd, "operations", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	o.registry, err = serviceaccountstore.Open(o.path("registry"))
	if err != nil {
		return nil, ErrUnavailable
	}
	if _, _, err := o.snapshot(); err != nil {
		return nil, err
	}
	success = true
	return o, nil
}

func closeSMBBackend(smbBackend smbprovision.Backend) {
	if closer, ok := smbBackend.(interface{ Close() error }); ok {
		_ = closer.Close()
	}
}

func privateDirectory(st unix.Stat_t) bool {
	return st.Mode&unix.S_IFMT == unix.S_IFDIR && st.Mode&07777 == 0700 && st.Uid == 0
}
func (o *Owner) path(name string) string { return fmt.Sprintf("/proc/self/fd/%d/%s", o.root, name) }
func (o *Owner) operationPath(id string) string {
	return fmt.Sprintf("/proc/self/fd/%d/%s", o.operations, id)
}

func (o *Owner) enter(ctx context.Context) error {
	if o == nil || ctx == nil || ctx.Err() != nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrUnavailable
	}
	if !o.mu.TryLock() {
		return ErrBusy
	}
	if o.closed || o.failed || o.registry == nil {
		o.mu.Unlock()
		return ErrUnavailable
	}
	return nil
}

// Close waits for this owner's current operation before releasing its lease.
func (o *Owner) Close() error {
	if o == nil {
		return nil
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || !o.ready {
		return nil
	}
	o.closed = true
	var err error
	for _, journal := range o.smbJournals {
		err = errors.Join(err, journal.Close())
	}
	if closer, ok := o.smbBackend.(interface{ Close() error }); ok {
		err = errors.Join(err, closer.Close())
	}
	o.smbBackend = nil
	o.deps.smbBackend = nil
	for _, journal := range o.journals {
		err = errors.Join(err, journal.Close())
	}
	if o.registry != nil {
		err = errors.Join(err, o.registry.Close())
	}
	if o.operations >= 0 {
		err = errors.Join(err, unix.Close(o.operations))
	}
	if o.root >= 0 {
		err = errors.Join(err, unix.Close(o.root))
	}
	if err != nil {
		return ErrUnavailable
	}
	return nil
}

// Snapshot returns fresh decoded state, never the authority's internal stores.
func (o *Owner) Snapshot(ctx context.Context) (serviceaccounts.Registry, []identityprovision.Journal, error) {
	if err := o.enter(ctx); err != nil {
		return serviceaccounts.Registry{}, nil, err
	}
	defer o.mu.Unlock()
	return o.snapshot()
}

// snapshot refuses missing/orphan/mismatched journals. Native account enablement,
// retirement and legacy import need a later credential-aware coordinator.
func (o *Owner) snapshot() (serviceaccounts.Registry, []identityprovision.Journal, error) {
	fail := func() (serviceaccounts.Registry, []identityprovision.Journal, error) {
		o.failed = true
		return serviceaccounts.Registry{}, nil, ErrUnavailable
	}
	r, err := o.registry.Load()
	if err != nil {
		return fail()
	}
	dir, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", o.operations))
	if err != nil {
		return fail()
	}
	entries, readErr := dir.ReadDir(serviceaccounts.MaxRecords + 1)
	closeErr := dir.Close()
	// ReadDir(n) returns EOF for an empty directory, which is valid for an empty ledger.
	if readErr != nil && !errors.Is(readErr, io.EOF) || closeErr != nil || len(entries) != len(r.Accounts) || r.Revision != uint64(len(r.Accounts))+1 {
		return fail()
	}
	known := make(map[string]bool, len(entries))
	for _, entry := range entries {
		known[entry.Name()] = true
	}
	result := make([]identityprovision.Journal, 0, len(r.Accounts))
	active := 0
	for i, a := range r.Accounts {
		if !known[a.ID] || a.State != serviceaccounts.Disabled {
			return fail()
		}
		var st unix.Stat_t
		if unix.Fstatat(o.operations, a.ID, &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !privateDirectory(st) || uint64(st.Dev) != o.device {
			return fail()
		}
		s := o.journals[a.ID]
		if s != nil && o.inodes[a.ID] != st.Ino {
			return fail()
		}
		if s == nil {
			s, err = identityprovision.Open(o.operationPath(a.ID))
			if err != nil {
				return fail()
			}
			o.journals[a.ID] = s
			o.inodes[a.ID] = st.Ino
		}
		j, loadErr := s.Load()
		if loadErr != nil || j.Account != a || j.RegistryRevision != uint64(i)+2 {
			return fail()
		}
		if o.loadSMBForAccount(a, j) != nil {
			return fail()
		}
		if j.Phase != identityprovision.UnixConfirmed {
			active++
			if j.RegistryRevision != r.Revision || active > 1 {
				return fail()
			}
		}
		result = append(result, j)
	}
	return r, result, nil
}

// loadSMBForAccount validates an optional child journal. Reopening an intent
// records review-required without observing or invoking Samba; the previous
// command's result can no longer be safely inferred or retried.
func (o *Owner) loadSMBForAccount(account serviceaccounts.Account, native identityprovision.Journal) error {
	accountFD, err := unix.Openat(o.operations, account.ID, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer unix.Close(accountFD)
	var parent unix.Stat_t
	if unix.Fstat(accountFD, &parent) != nil || !privateDirectory(parent) || uint64(parent.Dev) != o.device || o.inodes[account.ID] != parent.Ino {
		return ErrUnavailable
	}
	var st unix.Stat_t
	err = unix.Fstatat(accountFD, "smb", &st, unix.AT_SYMLINK_NOFOLLOW)
	if errors.Is(err, unix.ENOENT) {
		if o.smbJournals[account.ID] != nil || o.smbInodes[account.ID] != 0 {
			return ErrUnavailable
		}
		return nil
	}
	if err != nil || !privateDirectory(st) || uint64(st.Dev) != o.device {
		return ErrUnavailable
	}
	if native.Phase != identityprovision.UnixConfirmed {
		return ErrUnavailable
	}
	store := o.smbJournals[account.ID]
	if store != nil && o.smbInodes[account.ID] != st.Ino {
		return ErrUnavailable
	}
	if store == nil {
		store, err = smbprovision.Open(fmt.Sprintf("/proc/self/fd/%d/smb", accountFD), o.smbBackend)
		if err != nil {
			return err
		}
		o.smbJournals[account.ID] = store
		o.smbInodes[account.ID] = st.Ino
	}
	j, err := store.RecoverInterrupted()
	if err != nil || j.Account != account || j.NativeRevision != native.Revision {
		return ErrUnavailable
	}
	return nil
}

// Reserve persists the initial journal BEFORE publishing the reservation. A
// crash between documents leaves an orphan and refuses reopening, never silently
// frees/reuses its UID. Once both commits succeed, one native step may run.
func (o *Owner) Reserve(ctx context.Context, expected uint64, id, name string) (serviceaccounts.Account, error) {
	if err := o.enter(ctx); err != nil {
		return serviceaccounts.Account{}, err
	}
	defer o.mu.Unlock()
	r, journals, err := o.snapshot()
	if err != nil {
		return serviceaccounts.Account{}, err
	}
	if expected != r.Revision {
		return serviceaccounts.Account{}, ErrConflict
	}
	for _, j := range journals {
		if j.Phase != identityprovision.UnixConfirmed {
			if j.Phase == identityprovision.Reserved || j.Phase == identityprovision.GroupConfirmed {
				return serviceaccounts.Account{}, ErrPending
			}
			return serviceaccounts.Account{}, ErrReview
		}
	}
	external, err := o.deps.inventory(ctx)
	if err != nil {
		return serviceaccounts.Account{}, ErrUnavailable
	}
	if external.UIDs == nil || external.GIDs == nil || external.Names == nil {
		return serviceaccounts.Account{}, ErrUnavailable
	}
	if len(external.UIDs) > 65536 || len(external.GIDs) > 65536 || len(external.Names) > 65536 {
		return serviceaccounts.Account{}, ErrUnavailable
	}
	observed, err := o.deps.observe(ctx)
	if err != nil {
		return serviceaccounts.Account{}, ErrUnavailable
	}
	reserved, err := observed.Reservations()
	if err != nil {
		return serviceaccounts.Account{}, ErrUnavailable
	}
	reserved.UIDs = append(reserved.UIDs, external.UIDs...)
	reserved.GIDs = append(reserved.GIDs, external.GIDs...)
	reserved.Names = append(reserved.Names, external.Names...)
	next, err := r.Create(expected, id, name, reserved)
	if err != nil {
		return serviceaccounts.Account{}, ErrInvalid
	}
	if ctx.Err() != nil {
		return serviceaccounts.Account{}, ErrUnavailable
	}
	a := next.Accounts[len(next.Accounts)-1]
	// Any failure beyond this point quarantines this owner. Preserve evidence.
	fail := func() (serviceaccounts.Account, error) {
		o.failed = true
		return serviceaccounts.Account{}, ErrUnavailable
	}
	if unix.Mkdirat(o.operations, a.ID, 0700) != nil {
		return fail()
	}
	if unix.Fsync(o.operations) != nil {
		return fail()
	}
	j, err := identityprovision.Open(o.operationPath(a.ID))
	if err != nil {
		return fail()
	}
	o.journals[a.ID] = j
	var st unix.Stat_t
	if unix.Fstatat(o.operations, a.ID, &st, unix.AT_SYMLINK_NOFOLLOW) != nil {
		return fail()
	}
	o.inodes[a.ID] = st.Ino
	err = j.Begin(next, a.ID, observed)
	if err != nil || ctx.Err() != nil {
		return fail()
	}
	if o.deps.afterJournal != nil {
		o.deps.afterJournal()
	}
	if err := o.registry.Create(expected, id, name, reserved); err != nil {
		return fail()
	}
	if _, _, err := o.snapshot(); err != nil {
		return fail()
	}
	return a, nil
}

// Operation exposes only this owner's bound journal reads/steps to a local
// channel. Its ID is a lookup key, never used as a path before registry matching.
type Operation struct {
	owner *Owner
	id    string
}

func (o *Owner) Operation(id string) *Operation { return &Operation{owner: o, id: id} }

// SMBOperation is an in-process capability for managing the already-created
// Unix identity's Samba account lifecycle. Every method enters the same Owner
// mutex used by registry and Unix writers. It is not an HTTP or client API.
type SMBOperation struct {
	owner *Owner
	id    string
}

// SMB returns a lookup capability only; the identifier is resolved against
// the owner-validated registry before any filesystem path is formed.
func (o *Owner) SMB(id string) *SMBOperation { return &SMBOperation{owner: o, id: id} }

func findNative(journals []identityprovision.Journal, id string) (identityprovision.Journal, bool) {
	for _, journal := range journals {
		if journal.Account.ID == id {
			return journal, true
		}
	}
	return identityprovision.Journal{}, false
}

func (op *SMBOperation) current(ctx context.Context) (*Owner, identityprovision.Journal, *smbprovision.Store, error) {
	if op == nil || op.owner == nil {
		return nil, identityprovision.Journal{}, nil, ErrUnavailable
	}
	o := op.owner
	if err := o.enter(ctx); err != nil {
		return nil, identityprovision.Journal{}, nil, err
	}
	_, journals, err := o.snapshot()
	if err != nil {
		o.mu.Unlock()
		return nil, identityprovision.Journal{}, nil, err
	}
	native, ok := findNative(journals, op.id)
	if !ok {
		o.mu.Unlock()
		return nil, identityprovision.Journal{}, nil, ErrConflict
	}
	if native.Phase != identityprovision.UnixConfirmed {
		o.mu.Unlock()
		if native.Phase == identityprovision.ReviewRequired {
			return nil, identityprovision.Journal{}, nil, ErrReview
		}
		return nil, identityprovision.Journal{}, nil, errors.Join(ErrPending, smbprovision.ErrPending)
	}
	store := o.smbJournals[op.id]
	if store == nil {
		o.mu.Unlock()
		return nil, identityprovision.Journal{}, nil, smbprovision.ErrConflict
	}
	return o, native, store, nil
}

// Begin performs only read-only passdb observation and durable journal setup;
// the caller must pass the exact confirmed Unix journal revision. It refuses
// an existing passdb identity and never adopts it.
func (op *SMBOperation) Begin(ctx context.Context, nativeRevision uint64) error {
	if op == nil || op.owner == nil {
		return ErrUnavailable
	}
	o := op.owner
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer o.mu.Unlock()
	_, journals, err := o.snapshot()
	if err != nil {
		return err
	}
	native, ok := findNative(journals, op.id)
	if !ok {
		return ErrConflict
	}
	if native.Phase != identityprovision.UnixConfirmed {
		if native.Phase == identityprovision.ReviewRequired {
			return ErrReview
		}
		return errors.Join(ErrPending, smbprovision.ErrPending)
	}
	if native.Revision != nativeRevision {
		return ErrConflict
	}
	if err := o.verifyUnixLocked(ctx, native.Account); err != nil {
		return err
	}
	if existing := o.smbJournals[op.id]; existing != nil {
		journal, loadErr := existing.Load()
		if loadErr != nil {
			return o.smbFailure(loadErr)
		}
		if journal.Phase == smbprovision.ReviewRequired {
			return smbprovision.ErrReview
		}
		return smbprovision.ErrConflict
	}
	if o.smbInodes[op.id] != 0 {
		o.failed = true
		return ErrUnavailable
	}
	if ctx == nil || o.smbBackend == nil {
		return smbprovision.ErrInvalid
	}
	accountFD, err := unix.Openat(o.operations, op.id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnavailable
	}
	var parent unix.Stat_t
	if unix.Fstat(accountFD, &parent) != nil || !privateDirectory(parent) || uint64(parent.Dev) != o.device || o.inodes[op.id] != parent.Ino {
		unix.Close(accountFD)
		o.failed = true
		return ErrUnavailable
	}
	if err := unix.Mkdirat(accountFD, "smb", 0700); err != nil {
		unix.Close(accountFD)
		if errors.Is(err, unix.EEXIST) {
			o.failed = true
		}
		return ErrUnavailable
	}
	if unix.Fsync(accountFD) != nil {
		unix.Close(accountFD)
		o.failed = true
		return ErrUnavailable
	}
	var st unix.Stat_t
	if unix.Fstatat(accountFD, "smb", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || !privateDirectory(st) || uint64(st.Dev) != o.device {
		unix.Close(accountFD)
		o.failed = true
		return ErrUnavailable
	}
	store, err := smbprovision.Open(fmt.Sprintf("/proc/self/fd/%d/smb", accountFD), o.smbBackend)
	closeErr := unix.Close(accountFD)
	if err != nil || closeErr != nil {
		if store != nil {
			store.Close()
		}
		o.failed = true
		return ErrUnavailable
	}
	o.smbJournals[op.id] = store
	o.smbInodes[op.id] = st.Ino
	err = store.Begin(ctx, native.Revision, native.Account)
	if err == nil {
		return nil
	}
	// These errors occur before the store commits its first journal; remove only
	// the exact fresh, still-empty directory. Any uncertain commit is preserved.
	if errors.Is(err, smbprovision.ErrReview) || errors.Is(err, smbprovision.ErrObservation) ||
		errors.Is(err, smbprovision.ErrInvalid) || ctx.Err() != nil {
		if cleanupErr := o.discardFreshSMB(op.id, store, st.Ino); cleanupErr != nil {
			o.failed = true
			return ErrUnavailable
		}
		return err
	}
	o.failed = true
	return ErrUnavailable
}

func (o *Owner) discardFreshSMB(id string, store *smbprovision.Store, inode uint64) error {
	if _, err := store.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) {
		return ErrUnavailable
	}
	if err := store.Close(); err != nil {
		return ErrUnavailable
	}
	delete(o.smbJournals, id)
	delete(o.smbInodes, id)
	accountFD, err := unix.Openat(o.operations, id, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnavailable
	}
	defer unix.Close(accountFD)
	var st unix.Stat_t
	if unix.Fstatat(accountFD, "smb", &st, unix.AT_SYMLINK_NOFOLLOW) != nil || st.Ino != inode || !privateDirectory(st) || uint64(st.Dev) != o.device {
		return ErrUnavailable
	}
	smbFD, err := unix.Openat(accountFD, "smb", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return ErrUnavailable
	}
	entries, readErr := os.ReadDir(fmt.Sprintf("/proc/self/fd/%d", smbFD))
	var opened unix.Stat_t
	statErr := unix.Fstat(smbFD, &opened)
	closeErr := unix.Close(smbFD)
	if readErr != nil || statErr != nil || closeErr != nil || opened.Ino != inode || len(entries) != 0 {
		return ErrUnavailable
	}
	if unix.Unlinkat(accountFD, "smb", unix.AT_REMOVEDIR) != nil || unix.Fsync(accountFD) != nil {
		return ErrUnavailable
	}
	return nil
}

// Load returns the Samba-specific state through the owner lock.
func (op *SMBOperation) Load(ctx context.Context) (smbprovision.Journal, error) {
	o, _, store, err := op.current(ctx)
	if err != nil {
		return smbprovision.Journal{}, err
	}
	defer o.mu.Unlock()
	return store.Load()
}

// Step creates at most one disabled passdb record; a recovered/ambiguous intent
// is converted to review by the snapshot and is never dispatched again.
func (op *SMBOperation) Step(ctx context.Context, expected uint64) error {
	o, native, store, err := op.current(ctx)
	if err != nil {
		return err
	}
	defer o.mu.Unlock()
	journal, err := store.Load()
	if err != nil {
		return o.smbFailure(err)
	}
	if journal.NativeRevision != native.Revision || journal.Account != native.Account {
		o.failed = true
		return ErrUnavailable
	}
	if err := o.verifyUnixLocked(ctx, native.Account); err != nil {
		return err
	}
	if journal.Phase == smbprovision.ReviewRequired {
		return smbprovision.ErrReview
	}
	if o.smbBackend == nil {
		return smbprovision.ErrInvalid
	}
	err = store.Step(ctx, expected)
	return o.smbFailure(err)
}

// SetPasswordDisabled sends one secret through the trusted backend's stdin-only
// path; no credential bytes enter the owner journal or any client protocol.
func (op *SMBOperation) SetPasswordDisabled(ctx context.Context, expected uint64, secret []byte) error {
	o, native, store, err := op.current(ctx)
	if err != nil {
		return err
	}
	defer o.mu.Unlock()
	journal, err := store.Load()
	if err != nil {
		return o.smbFailure(err)
	}
	if journal.NativeRevision != native.Revision || journal.Account != native.Account {
		o.failed = true
		return ErrUnavailable
	}
	if err := o.verifyUnixLocked(ctx, native.Account); err != nil {
		return err
	}
	if journal.Phase == smbprovision.ReviewRequired {
		return smbprovision.ErrReview
	}
	if o.smbBackend == nil {
		return smbprovision.ErrInvalid
	}
	err = store.SetPasswordDisabled(ctx, expected, secret)
	return o.smbFailure(err)
}

// Enable is a separate explicit, revision-checked action. It never runs as a
// side effect of account creation or password assignment.
func (op *SMBOperation) Enable(ctx context.Context, expected uint64) error {
	o, native, store, err := op.current(ctx)
	if err != nil {
		return err
	}
	defer o.mu.Unlock()
	journal, err := store.Load()
	if err != nil {
		return o.smbFailure(err)
	}
	if journal.NativeRevision != native.Revision || journal.Account != native.Account {
		o.failed = true
		return ErrUnavailable
	}
	if err := o.verifyUnixLocked(ctx, native.Account); err != nil {
		return err
	}
	if journal.Phase == smbprovision.ReviewRequired {
		return smbprovision.ErrReview
	}
	if o.smbBackend == nil {
		return smbprovision.ErrInvalid
	}
	return o.smbFailure(store.Enable(ctx, expected))
}

// Disable is a separate explicit, revision-checked action. The Owner keeps
// the single trusted Samba backend bound at Open time; callers cannot supply
// or replace a backend for this operation. The journaled operation blocks new
// authentications, revokes this account's established SMB sessions and
// confirms their absence. Uncertain revocation is quarantined without replay;
// terminating sessions may interrupt active transfers or writes.
func (op *SMBOperation) Disable(ctx context.Context, expected uint64) error {
	o, native, store, err := op.current(ctx)
	if err != nil {
		return err
	}
	defer o.mu.Unlock()
	journal, err := store.Load()
	if err != nil {
		return o.smbFailure(err)
	}
	if journal.NativeRevision != native.Revision || journal.Account != native.Account {
		o.failed = true
		return ErrUnavailable
	}
	if err := o.verifyUnixLocked(ctx, native.Account); err != nil {
		return err
	}
	if journal.Phase == smbprovision.ReviewRequired {
		return smbprovision.ErrReview
	}
	if o.smbBackend == nil {
		return smbprovision.ErrInvalid
	}
	return o.smbFailure(store.Disable(ctx, expected))
}

func (o *Owner) verifyUnixLocked(ctx context.Context, account serviceaccounts.Account) error {
	if err := ctx.Err(); err != nil {
		return ErrUnavailable
	}
	observed, err := o.deps.observe(ctx)
	if err != nil {
		return ErrUnavailable
	}
	state, err := observed.Assess(account)
	if err != nil || state != unixidentity.Observed {
		return ErrReview
	}
	return nil
}

func (o *Owner) smbFailure(err error) error {
	if err == nil {
		return err
	}
	if errors.Is(err, revisionstore.ErrIO) || errors.Is(err, revisionstore.ErrUncertain) ||
		errors.Is(err, revisionstore.ErrUnsafe) || errors.Is(err, revisionstore.ErrInvalid) ||
		errors.Is(err, revisionstore.ErrNotInitialized) || errors.Is(err, revisionstore.ErrClosed) ||
		errors.Is(err, revisionstore.ErrConflict) {
		o.failed = true
		return ErrUnavailable
	}
	if errors.Is(err, smbprovision.ErrConflict) || errors.Is(err, smbprovision.ErrInvalid) ||
		errors.Is(err, smbprovision.ErrObservation) || errors.Is(err, smbprovision.ErrPending) || errors.Is(err, smbprovision.ErrReview) {
		return err
	}
	o.failed = true
	return ErrUnavailable
}

func (op *Operation) Load(ctx context.Context) (identityprovision.Journal, error) {
	if op == nil || op.owner == nil {
		return identityprovision.Journal{}, ErrUnavailable
	}
	o := op.owner
	if err := o.enter(ctx); err != nil {
		return identityprovision.Journal{}, err
	}
	defer o.mu.Unlock()
	_, journals, err := o.snapshot()
	if err != nil {
		return identityprovision.Journal{}, err
	}
	for _, j := range journals {
		if j.Account.ID == op.id {
			return j, nil
		}
	}
	return identityprovision.Journal{}, ErrConflict
}

func (op *Operation) Step(ctx context.Context, expected uint64) error {
	if op == nil || op.owner == nil {
		return ErrUnavailable
	}
	o := op.owner
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer o.mu.Unlock()
	r, journals, err := o.snapshot()
	if err != nil {
		return err
	}
	for _, j := range journals {
		if j.Account.ID != op.id {
			continue
		}
		if j.Revision != expected || j.RegistryRevision != r.Revision {
			return ErrConflict
		}
		if j.Phase == identityprovision.ReviewRequired {
			return ErrReview
		}
		s := o.journals[j.Account.ID]
		if s == nil {
			o.failed = true
			return ErrUnavailable
		}
		b, err := o.deps.executor(j.Account)
		if err != nil {
			return ErrUnavailable
		}
		err = s.Step(ctx, expected, r, b)
		closeErr := b.Close()
		if errors.Is(err, revisionstore.ErrIO) || errors.Is(err, revisionstore.ErrUncertain) || errors.Is(err, revisionstore.ErrUnsafe) || errors.Is(err, revisionstore.ErrInvalid) || errors.Is(err, revisionstore.ErrNotInitialized) || closeErr != nil {
			o.failed = true
			return ErrUnavailable
		}
		if errors.Is(err, identityprovision.ErrReview) {
			return ErrReview
		}
		if err != nil {
			return ErrUnavailable
		}
		return nil
	}
	return ErrConflict
}
