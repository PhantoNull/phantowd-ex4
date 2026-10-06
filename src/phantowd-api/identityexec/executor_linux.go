// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package identityexec executes only native private-group/user creation using
// the firmware BusyBox. It is not an authorization service or an HTTP backend.
package identityexec

import (
	"context"
	"errors"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
	"golang.org/x/sys/unix"
)

var (
	ErrInvalid = errors.New("invalid native identity command")
	ErrUnsafe  = errors.New("native identity executor unavailable or unsafe")
	ErrBusy    = errors.New("native identity executor busy")
	ErrClosed  = errors.New("native identity executor closed")
	ErrState   = errors.New("native identity command precondition or result mismatch")
	ErrCommand = errors.New("native identity command failed; reconcile journal")
)

// Executor is bound to one validated, disabled reservation. The caller must
// retain authority over the registry, operation journal, /etc and ALL identity
// writers throughout the operation. This object's mutex is not that authority.
// Never copy it. No public path, executable, argument, password or shell option.
type Executor struct {
	mu          sync.Mutex
	expected    serviceaccounts.Account
	binary      *os.File
	before      unix.Stat_t
	requireRoot bool
	// Private seams permit host tests without changing host account databases.
	observe func() (unixidentity.Snapshot, error)
	run     func(context.Context, *os.File, []string, time.Duration) error
}

// Open requires root and pins the fixed firmware ELF before any command. It
// does not prove reservation ownership, disk/NSS completeness or durable /etc.
// Only the guarded QEMU caller currently wires it to identityprovision.Store.
func Open(a serviceaccounts.Account) (*Executor, error) {
	if !validAccount(a) {
		return nil, ErrInvalid
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrUnsafe
	}
	f, st, err := pinBinary("/bin/busybox", 0)
	if err != nil {
		return nil, err
	}
	return &Executor{expected: a, binary: f, before: st, requireRoot: true,
		observe: func() (unixidentity.Snapshot, error) { return unixidentity.ReadLocal("/etc", 0) }, run: runPinned}, nil
}

func validAccount(a serviceaccounts.Account) bool {
	r, err := serviceaccounts.New(a.UID, a.UID)
	r.Accounts = []serviceaccounts.Account{a}
	return err == nil && r.Validate() == nil && a.State == serviceaccounts.Disabled
}

func (e *Executor) Close() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.binary == nil {
		return nil
	}
	err := e.binary.Close()
	e.binary = nil
	if err != nil {
		return ErrUnsafe
	}
	return nil
}

func (e *Executor) enter(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !e.mu.TryLock() {
		return ErrBusy
	}
	if e.binary == nil || e.observe == nil || e.run == nil {
		e.mu.Unlock()
		return ErrClosed
	}
	return nil
}

func (e *Executor) Observe(ctx context.Context) (unixidentity.Snapshot, error) {
	if err := e.enter(ctx); err != nil {
		return unixidentity.Snapshot{}, err
	}
	defer e.mu.Unlock()
	s, err := e.observe()
	if err != nil {
		return unixidentity.Snapshot{}, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return unixidentity.Snapshot{}, err
	}
	return s, nil
}

func (e *Executor) CreateGroup(ctx context.Context, a serviceaccounts.Account) error {
	return e.create(ctx, a, false)
}

func (e *Executor) CreateUser(ctx context.Context, a serviceaccounts.Account) error {
	return e.create(ctx, a, true)
}

func (e *Executor) create(ctx context.Context, a serviceaccounts.Account, user bool) error {
	if !validAccount(a) || a != e.expected {
		return ErrInvalid
	}
	if err := e.enter(ctx); err != nil {
		return err
	}
	defer e.mu.Unlock()
	if e.requireRoot && (os.Getuid() != 0 || os.Geteuid() != 0) {
		return ErrUnsafe
	}
	var st unix.Stat_t
	if unix.Fstat(int(e.binary.Fd()), &st) != nil || !sameBinary(st, e.before) {
		return ErrUnsafe
	}
	before, err := e.observe()
	if err != nil {
		return ErrUnsafe
	}
	detail, err := before.Inspect(a)
	if err != nil || (!user && detail.Status != unixidentity.Absent) ||
		(user && !(detail.Status == unixidentity.Partial && detail.GroupPresent && !detail.UserPresent)) {
		return ErrState
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	args := []string{"addgroup", "-g", strconv.FormatUint(uint64(a.GID), 10), a.Name}
	if user {
		// -D: do not launch passwd; -H: no home creation. There is no password,
		// shell, group membership or arbitrary UID override supplied by a client.
		args = []string{"adduser", "-D", "-H", "-s", "/sbin/nologin", "-G", a.Name, "-u", strconv.FormatUint(uint64(a.UID), 10), a.Name}
	}
	if err := e.run(ctx, e.binary, args, 5*time.Second); err != nil {
		return ErrCommand
	}
	if ctx.Err() != nil {
		return ErrCommand
	}
	if unix.Fstat(int(e.binary.Fd()), &st) != nil || !sameBinary(st, e.before) {
		return ErrCommand
	}
	after, err := e.observe()
	if err != nil || ctx.Err() != nil {
		return ErrCommand
	}
	detail, err = after.Inspect(a)
	if err != nil || (user && detail.Status != unixidentity.Observed) ||
		(!user && !(detail.Status == unixidentity.Partial && detail.GroupPresent && !detail.UserPresent)) {
		return ErrState
	}
	return nil
}
