//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"golang.org/x/sys/unix"
)

// stageNASEvidenceRole is one private publication step, not a transaction or
// authority constructor. The future coordinator must retain the original locked
// root, authorize replacement, validate bytes/transition and account for its own
// watch events across ALL stages. This helper never resets a watch, removes an
// entry, opens an Owner or authorizes retry. Any attempted uncertain I/O requires
// sticky review in that coordinator; a matching readback alone is not admission.
func stageNASEvidenceRole(ctx context.Context, root *os.File, role string, data []byte, ops fileOps) error {
	limit := naspolicy.MaxInputBytes
	switch role {
	case ".nas-services.intent", ".nas-services.receipt":
		limit = naspolicyevidence.MaxRecordBytes
	case "nas-services.json", ".nas-services.base":
	default:
		return ErrInvalid
	}
	if ctx == nil || root == nil || len(data) == 0 || len(data) > limit ||
		ops.write == nil || ops.sync == nil || ops.close == nil || ops.rename == nil || ops.syncDir == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	dir := int(root.Fd())
	var original unix.Stat_t
	if unix.Fstat(dir, &original) != nil || original.Mode != unix.S_IFDIR|0700 || original.Uid != uint32(os.Geteuid()) {
		return ErrUnsafe
	}
	var previous unix.Stat_t
	absent := false
	if err := unix.Fstatat(dir, role, &previous, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT); errors.Is(err, unix.ENOENT) {
		absent = true
	} else if err != nil || previous.Mode != unix.S_IFREG|0600 || previous.Uid != original.Uid || previous.Nlink != 1 || previous.Dev != original.Dev || previous.Size < 0 || previous.Size > int64(limit) {
		return ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	const pending = ".nas-services.pending"
	fd, err := unix.Openat2(dir, pending, &unix.OpenHow{
		Flags: unix.O_WRONLY | unix.O_CREAT | unix.O_EXCL | unix.O_NOFOLLOW | unix.O_CLOEXEC,
		Mode:  0600, Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return ErrReview // Existing pending is evidence, never disposable staging.
	}
	f := os.NewFile(uintptr(fd), "nas-evidence-pending")
	n, writeErr := ops.write(f, data)
	var syncErr error
	if writeErr == nil && n == len(data) && ctx.Err() == nil {
		syncErr = ops.sync(f)
	}
	var staged unix.Stat_t
	statErr := unix.Fstat(fd, &staged)
	closeErr := ops.close(f) // Exactly one attempt, including write/sync errors.
	if writeErr != nil || n != len(data) || syncErr != nil || statErr != nil || closeErr != nil || ctx.Err() != nil ||
		staged.Mode != unix.S_IFREG|0600 || staged.Uid != original.Uid || staged.Nlink != 1 || staged.Dev != original.Dev || staged.Size != int64(len(data)) {
		return ErrReview
	}
	var named unix.Stat_t
	if unix.Fstatat(dir, pending, &named, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil || policyStamp(named) != policyStamp(staged) {
		return ErrReview
	}
	err = unix.Fstatat(dir, role, &named, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT)
	if (absent && !errors.Is(err, unix.ENOENT)) || (!absent && (err != nil || policyStamp(named) != policyStamp(previous))) || ctx.Err() != nil {
		return ErrReview
	}
	if ops.rename(dir, pending, dir, role) != nil || ctx.Err() != nil || ops.syncDir(dir) != nil || ctx.Err() != nil {
		return ErrReview
	}
	var final, directory unix.Stat_t
	if unix.Fstatat(dir, role, &final, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT) != nil ||
		final.Dev != staged.Dev || final.Ino != staged.Ino || final.Mode != staged.Mode || final.Uid != staged.Uid || final.Gid != staged.Gid || final.Nlink != 1 || final.Size != staged.Size || final.Mtim != staged.Mtim ||
		unix.Fstat(dir, &directory) != nil || directory.Dev != original.Dev || directory.Ino != original.Ino || directory.Mode != original.Mode || directory.Uid != original.Uid || directory.Gid != original.Gid {
		return ErrReview
	}
	got, err := readNASEvidenceRole(ctx, dir, role, limit, final)
	if err != nil || !bytes.Equal(got, data) || ctx.Err() != nil {
		return errors.Join(ErrReview, ErrIO)
	}
	return nil
}
