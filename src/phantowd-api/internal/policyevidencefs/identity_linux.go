//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/identityevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

type identityDirectory struct {
	allowed    map[string]bool
	limit      int
	operations bool
}
type identityAccount struct {
	name          string
	native, samba int
}
type identityLayout struct {
	dirs        []object
	names       []map[string]stamp
	directories []identityDirectory
	files       []object
	roles       []roleSpec
	accounts    []identityAccount
}

func (s *state) namesAt(index int) map[string]stamp {
	if s.identities != nil {
		return s.identities.names[index]
	}
	return s.names[index]
}

// Reuse the domain's actual ID grammar; this fixed dummy user is validation
// DATA only, never a native allocation, account, directory or imported name.
func identityRoleName(name string) bool {
	c := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1, Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{{ID: name, Name: "role"}}, Shares: []shareconfig.Share{}}
	return c.Validate() == nil
}

// OpenIdentity explicitly selects root/registry/operations/<account>/[smb].
// Root-only, no Store/Owner construction, synchronization, repair or runtime I/O.
// Cooperating writers/trusted parents remain external prerequisites. A nonnil
// handle WITH error is retained reviewed cleanup, never successful opening.
func OpenIdentity(ctx context.Context, directory string) (observer *Observer, result error) {
	if ctx == nil || !filepath.IsAbs(directory) || filepath.Clean(directory) != directory {
		return nil, ErrInvalid
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	s := &state{path: directory, watch: -1, identities: &identityLayout{}, closeFile: func(f *os.File) error { return f.Close() }, readAt: func(f *os.File, b []byte, off int64) (int, error) { return f.ReadAt(b, off) }}
	a := &Observer{state: s}
	s.self = a
	defer func() {
		if result != nil && a.Close() != nil {
			observer = a
			result = errors.Join(ErrReview, result)
		}
	}()
	var proc unix.Statfs_t
	if unix.Statfs("/proc/self/fd", &proc) != nil || proc.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrUnsupported
	}
	var err error
	s.watch, err = unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		return nil, ErrIO
	}
	if err = s.openIdentityDirectory(ctx, -1, directory, identityDirectory{allowed: map[string]bool{"registry": true, "operations": true}, limit: 2}); err != nil {
		return nil, err
	}
	if err = s.openIdentityDirectory(ctx, 0, "registry", identityDirectory{allowed: map[string]bool{"service-accounts.json": false, ".service-accounts.pending": false}, limit: 2}); err != nil {
		return nil, err
	}
	if err = s.openIdentityDirectory(ctx, 0, "operations", identityDirectory{limit: serviceaccounts.MaxRecords, operations: true}); err != nil {
		return nil, err
	}
	x := s.identities
	if len(x.names[0]) != 2 {
		return nil, ErrUnsafe
	}
	x.roles = []roleSpec{{1, "service-accounts.json", serviceaccounts.MaxInputBytes}}
	names := make([]string, 0, len(x.names[2]))
	for name := range x.names[2] {
		names = append(names, name)
	}
	slices.Sort(names)
	_, s.review = x.names[1][".service-accounts.pending"]
	remaining := identityevidence.MaxInputBytes
	for _, name := range names {
		remaining -= len(name)
		if remaining < 0 {
			return nil, ErrUnsafe
		}
		index := len(x.dirs)
		if err = s.openIdentityDirectory(ctx, 2, name, identityDirectory{allowed: map[string]bool{"identity-operation.json": false, ".identity-operation.pending": false, "smb": true}, limit: 3}); err != nil {
			return nil, err
		}
		_, pending := x.names[index][".identity-operation.pending"]
		s.review = s.review || pending
		account := identityAccount{name: name, native: len(x.roles), samba: -1}
		x.roles = append(x.roles, roleSpec{index, "identity-operation.json", identityprovision.MaxBytes})
		if _, present := x.names[index]["smb"]; present {
			child := len(x.dirs)
			if err = s.openIdentityDirectory(ctx, index, "smb", identityDirectory{allowed: map[string]bool{"smb-operation.json": false, ".smb-operation.pending": false}, limit: 2}); err != nil {
				return nil, err
			}
			_, pending = x.names[child][".smb-operation.pending"]
			s.review = s.review || pending
			account.samba = len(x.roles)
			x.roles = append(x.roles, roleSpec{child, "smb-operation.json", smbprovision.MaxBytes})
		}
		x.accounts = append(x.accounts, account)
	}
	for _, role := range x.roles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if st, present := x.names[role.parent][role.name]; present {
			if st.size == 0 || st.size > uint64(role.limit) || st.size > uint64(remaining) {
				return nil, ErrUnsafe
			}
			remaining -= int(st.size)
		}
	}
	x.files = make([]object, len(x.roles))
	for i, role := range x.roles {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		st, present := x.names[role.parent][role.name]
		if !present {
			continue
		}
		f, e := openFile(int(x.dirs[role.parent].file.Fd()), role.name, false, confined)
		if e != nil {
			return nil, e
		}
		x.files[i].file = f
		actual, e := statFD(f)
		if e != nil || actual != st {
			return nil, ErrReview
		}
		x.files[i].initial = actual
		if err = s.watchFile(f, false); err != nil {
			return nil, err
		}
	}
	if err = s.verify(ctx); err != nil {
		return nil, err
	}
	return a, nil
}

func (s *state) openIdentityDirectory(ctx context.Context, parent int, name string, spec identityDirectory) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	x := s.identities
	parentFD, resolve := unix.AT_FDCWD, uint64(unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if parent >= 0 {
		parentFD = int(x.dirs[parent].file.Fd())
		resolve = confined
	}
	f, err := openFile(parentFD, name, true, resolve)
	if err != nil {
		return err
	}
	index := len(x.dirs)
	x.dirs = append(x.dirs, object{file: f})
	x.names = append(x.names, nil)
	x.directories = append(x.directories, spec)
	st, err := statFD(f)
	if err != nil {
		return err
	}
	if !owned(st, true) || index > 0 && !sameMedium(st, x.dirs[0].initial) {
		return ErrUnsafe
	}
	for _, other := range x.dirs[:index] {
		if other.initial.ino == st.ino && sameMedium(other.initial, st) {
			return ErrUnsafe
		}
	}
	if parent >= 0 {
		if expected, found := x.names[parent][name]; !found || expected != st {
			return ErrReview
		}
	}
	x.dirs[index].initial = st
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return ErrBusy
		}
		return ErrIO
	}
	if err = s.watchFile(f, true); err != nil {
		return err
	}
	x.names[index], err = s.censusIdentity(ctx, index)
	return err
}

func (s *state) censusIdentity(ctx context.Context, index int) (found map[string]stamp, result error) {
	x := s.identities
	parent := x.dirs[index]
	spec := x.directories[index]
	cursor, err := openFile(int(parent.file.Fd()), ".", true, confined)
	if err != nil {
		return nil, err
	}
	defer func() {
		if s.closeTemporary(cursor) != nil {
			found, result = nil, ErrReview
		}
	}()
	st, err := statFD(cursor)
	if err != nil || st != parent.initial {
		return nil, ErrReview
	}
	found = make(map[string]stamp)
	for {
		if err = ctx.Err(); err != nil {
			return nil, err
		}
		names, e := cursor.Readdirnames(1)
		if len(names) == 0 && errors.Is(e, io.EOF) {
			break
		}
		if e != nil || len(names) != 1 {
			return nil, ErrIO
		}
		name := names[0]
		dir, permitted := spec.allowed[name]
		if spec.operations {
			dir, permitted = true, identityRoleName(name)
		}
		if _, duplicate := found[name]; duplicate || !permitted || len(found) >= spec.limit {
			return nil, ErrUnsafe
		}
		st, e := statAt(int(parent.file.Fd()), name, unix.AT_SYMLINK_NOFOLLOW)
		if e != nil {
			return nil, e
		}
		if !owned(st, dir) || !sameMedium(st, x.dirs[0].initial) {
			return nil, ErrUnsafe
		}
		found[name] = st
	}
	st, err = statFD(parent.file)
	if err != nil || st != parent.initial {
		return nil, ErrReview
	}
	return found, nil
}

func (s *state) matchIdentity(slots []policyevidence.Slot) (identityevidence.Diagnosis, error) {
	x := s.identities
	if x == nil || len(slots) != len(x.roles) || len(slots) == 0 {
		return identityevidence.Diagnosis{}, ErrInvalid
	}
	entries := make([]identityevidence.Entry, len(x.accounts))
	for i, a := range x.accounts {
		smb := policyevidence.Slot{State: policyevidence.Absent}
		if a.samba >= 0 {
			smb = slots[a.samba]
			if smb.State == policyevidence.Absent {
				smb.State = policyevidence.Unavailable
			}
		}
		entries[i] = identityevidence.Entry{AccountID: a.name, Native: slots[a.native], Samba: smb}
	}
	return identityevidence.Match(slots[0], entries)
}

func (a *Observer) ObserveIdentity(ctx context.Context) (identityevidence.Diagnosis, error) {
	d, err := a.observe(ctx, identityObservation)
	return d.identities, err
}
