//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package iscsicredentials

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"golang.org/x/sys/unix"
)

const (
	InitialRole  = "iscsi-credentials"
	InitialStage = ".iscsi-credentials.provisioning"
)

// ProvisionInitial publishes one credential role under the caller's admitted,
// locked RC0 state directory. The caller retains the confirmed policy and
// excludes live readers. A failed durable stage remains for review.
func ProvisionInitial(ctx context.Context, parent *os.File, policy *naspolicystore.Lease, input io.Reader) (result error) {
	if ctx == nil || ctx.Err() != nil || parent == nil || policy == nil || input == nil ||
		os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(input, maxBytes+1))
	defer clear(raw)
	if err != nil || len(raw) > maxBytes {
		return ErrInvalid
	}
	doc, err := decode(bytes.NewReader(raw))
	if err != nil || doc.Revision != 1 || len(doc.Entries) == 0 {
		return ErrInvalid
	}
	confirmed, err := policy.Snapshot(ctx)
	if err != nil {
		return ErrReview
	}
	if count, err := matchPolicyCredentials(confirmed, credentialValues(doc)); err != nil || count != len(doc.Entries) {
		return ErrInvalid
	}
	if ctx.Err() != nil {
		return ErrUnavailable
	}

	fd := int(parent.Fd())
	var info unix.Stat_t
	if unix.Fstat(fd, &info) != nil || info.Mode != unix.S_IFDIR|0700 || info.Uid != 0 {
		return ErrUnavailable
	}
	for _, name := range []string{InitialStage, InitialRole} {
		if err := unix.Fstatat(fd, name, &info, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT); !errors.Is(err, unix.ENOENT) {
			return ErrReview
		}
	}
	if unix.Mkdirat(fd, InitialStage, 0700) != nil || unix.Fsync(fd) != nil {
		return ErrReview
	}
	staged, err := unix.Openat2(fd, InitialStage, &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return ErrReview
	}
	dir := os.NewFile(uintptr(staged), "iscsi-credential-stage")
	defer func() {
		if dir.Close() != nil {
			result = errors.Join(result, ErrReview)
		}
	}()
	if unix.Fchown(staged, 0, 0) != nil || unix.Fchmod(staged, 0700) != nil {
		return ErrReview
	}
	store, err := revisionstore.OpenDirectoryWithCodec(dir, codec())
	if err != nil {
		return ErrReview
	}
	if err := errors.Join(store.CommitPristine(doc), store.Close(), policy.Verify(ctx)); err != nil {
		return ErrReview
	}
	var named unix.Stat_t
	if unix.Fstat(staged, &info) != nil ||
		unix.Fstatat(fd, InitialStage, &named, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil ||
		info.Dev != named.Dev || info.Ino != named.Ino || named.Mode != unix.S_IFDIR|0700 ||
		named.Uid != 0 || named.Gid != 0 ||
		unix.Renameat2(fd, InitialStage, fd, InitialRole, unix.RENAME_NOREPLACE) != nil || unix.Fsync(fd) != nil {
		return ErrReview
	}
	return nil
}
