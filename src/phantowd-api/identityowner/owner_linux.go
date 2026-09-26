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
	afterJournal func() // private process-interruption test seam
}

type Owner struct {
	mu                    sync.Mutex
	root, operations      int
	device                uint64
	registry              *serviceaccountstore.Store
	journals              map[string]*identityprovision.Store
	inodes                map[string]uint64
	deps                  dependencies
	failed, closed, ready bool
}

// Open requires pre-provisioned root-owned 0700 root/registry/operations
// directories on one local filesystem and an explicitly initialized empty or
// previously owner-managed registry. It never bootstraps, imports or repairs.
func Open(directory string, inventory Inventory) (*Owner, error) {
	return open(directory, dependencies{
		inventory: inventory,
		observe: func(ctx context.Context) (unixidentity.Snapshot, error) {
			if err := ctx.Err(); err != nil {
				return unixidentity.Snapshot{}, err
			}
			return unixidentity.ReadLocal("/etc", 0)
		},
		executor: func(a serviceaccounts.Account) (backend, error) { return identityexec.Open(a) },
	})
}

func open(directory string, deps dependencies) (*Owner, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || deps.inventory == nil || deps.observe == nil || deps.executor == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, directory, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrUnavailable
	}
	o := &Owner{root: fd, operations: -1, deps: deps, journals: make(map[string]*identityprovision.Store), inodes: make(map[string]uint64), ready: true}
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
