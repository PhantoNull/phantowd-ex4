// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"io"
	"os"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
	"golang.org/x/sys/unix"
)

const (
	nativeIdentityDirectory = "native"
	nativeIdentityMarker    = "native-profile-v1"
	nativeIdentityFile      = "identities.json"
	nativeIdentityFormat    = "phantowd-managed-native-identities-v1"
	nativeIdentityLimit     = 64 << 10
	nativeGroup             = "group"
	nativeUser              = "user"
)

type nativeIdentityRecord struct {
	Account serviceaccounts.Account `json:"account"`
	Stage   string                  `json:"stage"`
}

type nativeIdentityDocument struct {
	Format   string                 `json:"format"`
	Revision uint64                 `json:"revision"`
	Records  []nativeIdentityRecord `json:"records"`
}

func nativeIdentityCodec() revisionstore.Codec[nativeIdentityDocument] {
	return revisionstore.Codec[nativeIdentityDocument]{
		CurrentName: nativeIdentityFile, PendingName: ".identities.pending", MaxBytes: nativeIdentityLimit,
		Decode: func(input io.Reader) (nativeIdentityDocument, error) {
			keys := map[string]bool{"format": true, "revision": true, "records": true, "stage": true,
				"account": true, "id": true, "name": true, "uid": true, "gid": true, "state": true}
			var document nativeIdentityDocument
			if configjson.Decode(input, &document, nativeIdentityLimit, 6, keys) != nil || validateNativeDocument(document) != nil {
				return nativeIdentityDocument{}, ErrReview
			}
			return document, nil
		},
		Validate: validateNativeDocument, Revision: func(document nativeIdentityDocument) uint64 { return document.Revision },
		ValidateTransition: validateNativeTransition,
	}
}

func validateNativeDocument(document nativeIdentityDocument) error {
	if document.Format != nativeIdentityFormat || document.Records == nil || len(document.Records) > serviceaccounts.MaxLive {
		return ErrReview
	}
	accounts, err := serviceaccounts.New(1000, 60000)
	if err != nil {
		return ErrReview
	}
	var events uint64 = 1
	for i, record := range document.Records {
		if record.Account.State != serviceaccounts.Disabled ||
			(record.Stage != nativeUser && (record.Stage != nativeGroup || i != len(document.Records)-1)) {
			return ErrReview
		}
		accounts.Accounts = append(accounts.Accounts, record.Account)
		events++
		if record.Stage == nativeUser {
			events++
		}
	}
	if accounts.Validate() != nil || document.Revision != events {
		return ErrReview
	}
	return nil
}

func validateNativeTransition(previous, next nativeIdentityDocument) error {
	count := len(previous.Records)
	if len(next.Records) == count+1 && slices.Equal(previous.Records, next.Records[:count]) && next.Records[count].Stage == nativeGroup {
		return nil
	}
	if count > 0 && len(next.Records) == count && slices.Equal(previous.Records[:count-1], next.Records[:count-1]) {
		from, to := previous.Records[count-1], next.Records[count-1]
		if from.Account == to.Account && from.Stage == nativeGroup && to.Stage == nativeUser {
			return nil
		}
	}
	return ErrReview
}

func initializeNativeIdentityRole(parent int) error {
	if err := unix.Mkdirat(parent, nativeIdentityDirectory, 0700); err != nil {
		return err
	}
	fd, _, err := openPrivateDirectoryAt(parent, nativeIdentityDirectory)
	if err != nil {
		return err
	}
	dir := os.NewFile(uintptr(fd), "native-identity-stage")
	store, err := revisionstore.OpenDirectoryWithCodec(dir, nativeIdentityCodec())
	if err != nil {
		return errors.Join(err, dir.Close())
	}
	document := nativeIdentityDocument{Format: nativeIdentityFormat, Revision: 1, Records: []nativeIdentityRecord{}}
	if err := errors.Join(store.CommitPristine(document), store.Close(), dir.Close()); err != nil {
		return err
	}
	marker, err := unix.Openat(parent, nativeIdentityMarker, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	return errors.Join(unix.Fchown(marker, 0, 0), unix.Fchmod(marker, 0600), unix.Fsync(marker), unix.Close(marker))
}

type nativeIdentityState struct {
	parent int
	dir    *os.File
	store  *revisionstore.Store[nativeIdentityDocument]
	inode  unix.Stat_t
	base   func(context.Context) (unixidentity.Snapshot, error)
}

func openNativeIdentityState(parent int, base func(context.Context) (unixidentity.Snapshot, error)) (*nativeIdentityState, error) {
	marked, err := inspectNativeIdentityMarker(parent)
	if err != nil {
		return nil, err
	}
	fd, identity, err := openPrivateDirectoryAt(parent, nativeIdentityDirectory)
	if !marked && errors.Is(err, unix.ENOENT) {
		return nil, nil // Existing provisioned ledgers may predate this role.
	}
	if marked && errors.Is(err, unix.ENOENT) {
		return nil, ErrReview
	}
	if err != nil {
		return nil, err
	}
	if !marked {
		return nil, errors.Join(ErrReview, unix.Close(fd))
	}
	dir := os.NewFile(uintptr(fd), "native-identity-state")
	store, err := revisionstore.OpenDirectoryWithCodec(dir, nativeIdentityCodec())
	if err != nil {
		return nil, errors.Join(err, dir.Close())
	}
	state := &nativeIdentityState{parent: parent, dir: dir, store: store, inode: identity, base: base}
	if _, err := state.load(); err != nil {
		return nil, errors.Join(err, state.close())
	}
	return state, nil
}

func inspectNativeIdentityMarker(parent int) (bool, error) {
	var stat unix.Stat_t
	err := unix.Fstatat(parent, nativeIdentityMarker, &stat, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
	if errors.Is(err, unix.ENOENT) {
		return false, nil
	}
	if err != nil || stat.Mode != unix.S_IFREG|0600 || stat.Uid != 0 || stat.Gid != 0 || stat.Nlink != 1 || stat.Size != 0 {
		return false, ErrReview
	}
	return true, nil
}

func (s *nativeIdentityState) close() error {
	return errors.Join(s.store.Close(), s.dir.Close())
}

func (s *nativeIdentityState) load() (nativeIdentityDocument, error) {
	if marked, err := inspectNativeIdentityMarker(s.parent); err != nil || !marked {
		return nativeIdentityDocument{}, ErrReview
	}
	fd, stat, err := openPrivateDirectoryAt(s.parent, nativeIdentityDirectory)
	if err != nil {
		return nativeIdentityDocument{}, ErrReview
	}
	dir := os.NewFile(uintptr(fd), "native-identity-census")
	// A pending document or another file is preserved for offline review.
	names, readErr := dir.Readdirnames(2)
	if dir.Close() != nil || stat.Dev != s.inode.Dev || stat.Ino != s.inode.Ino ||
		(readErr != nil && !errors.Is(readErr, io.EOF)) || len(names) != 1 || names[0] != nativeIdentityFile {
		return nativeIdentityDocument{}, ErrReview
	}
	return s.store.Load()
}

func (s *nativeIdentityState) observe(ctx context.Context) (unixidentity.Snapshot, error) {
	document, err := s.load()
	if err != nil {
		return unixidentity.Snapshot{}, err
	}
	return s.project(ctx, document)
}

func (s *nativeIdentityState) project(ctx context.Context, document nativeIdentityDocument) (unixidentity.Snapshot, error) {
	base, err := s.base(ctx)
	if err != nil {
		return unixidentity.Snapshot{}, err
	}
	records := make([]unixidentity.ManagedIdentity, 0, len(document.Records))
	for _, record := range document.Records {
		records = append(records, unixidentity.ManagedIdentity{Account: record.Account, UserPresent: record.Stage == nativeUser})
	}
	return base.WithManagedIdentities(records)
}

func (s *nativeIdentityState) reconcile(journals []identityprovision.Journal) error {
	document, err := s.load()
	if err != nil {
		return err
	}
	position := 0
	for _, journal := range journals {
		var stage string
		if position < len(document.Records) && document.Records[position].Account == journal.Account {
			stage = document.Records[position].Stage
			position++
		}
		acceptable := false
		switch journal.Phase {
		case identityprovision.Reserved:
			acceptable = stage == ""
		case identityprovision.GroupIntent:
			acceptable = stage == "" || stage == nativeGroup
		case identityprovision.GroupConfirmed:
			acceptable = stage == nativeGroup
		case identityprovision.UserIntent:
			acceptable = stage == nativeGroup || stage == nativeUser
		case identityprovision.UnixConfirmed:
			acceptable = stage == nativeUser
		case identityprovision.ReviewRequired:
			acceptable = true // Preserve the observed effect of interrupted work.
		}
		if !acceptable {
			return ErrReview
		}
	}
	if position != len(document.Records) {
		return ErrReview
	}
	return nil
}

func (s *nativeIdentityState) bind(account serviceaccounts.Account) (backend, error) {
	return &nativeIdentityOperation{state: s, account: account}, nil
}

type nativeIdentityOperation struct {
	state   *nativeIdentityState
	account serviceaccounts.Account
}

func (o *nativeIdentityOperation) Observe(ctx context.Context) (unixidentity.Snapshot, error) {
	return o.state.observe(ctx)
}

func (*nativeIdentityOperation) Close() error { return nil }

func (o *nativeIdentityOperation) CreateGroup(ctx context.Context, account serviceaccounts.Account) error {
	return o.apply(ctx, account, nativeGroup)
}

func (o *nativeIdentityOperation) CreateUser(ctx context.Context, account serviceaccounts.Account) error {
	return o.apply(ctx, account, nativeUser)
}

func (o *nativeIdentityOperation) apply(ctx context.Context, account serviceaccounts.Account, stage string) error {
	if account != o.account || ctx == nil || ctx.Err() != nil {
		return ErrInvalid
	}
	document, err := o.state.load()
	if err != nil {
		return err
	}
	before, err := o.state.project(ctx, document)
	if err != nil {
		return err
	}
	observed, err := before.Inspect(account)
	if err != nil {
		return err
	}
	switch stage {
	case nativeGroup:
		if observed.Status != unixidentity.Absent {
			return ErrConflict
		}
		document.Records = append(document.Records, nativeIdentityRecord{Account: account, Stage: nativeGroup})
	case nativeUser:
		last := len(document.Records) - 1
		if last < 0 || document.Records[last] != (nativeIdentityRecord{Account: account, Stage: nativeGroup}) ||
			observed.Status != unixidentity.Partial || !observed.GroupPresent || observed.UserPresent {
			return ErrConflict
		}
		document.Records[last].Stage = nativeUser
	default:
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	expected := document.Revision
	document.Revision++
	return o.state.store.Commit(expected, document)
}
