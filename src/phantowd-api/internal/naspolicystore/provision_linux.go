//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicystore

import (
	"bytes"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"golang.org/x/sys/unix"
)

const (
	initialPolicyName = "nas-policy"
	initialStageName  = ".nas-policy.provisioning"
)

// ProvisionInitial publishes a fresh policy from independently supplied bytes.
// The caller owns the private, qualified parent and excludes other writers and
// consumers. It retains the input for future confirmation. An interrupted
// staging directory requires review and cannot be resumed by this operation.
func ProvisionInitial(parent *os.File, installation string, confirmed []byte) (result error) {
	if parent == nil || len(confirmed) > naspolicy.MaxInputBytes {
		return ErrInvalid
	}
	policy, err := naspolicy.Decode(bytes.NewReader(confirmed))
	if err != nil || policy.Revision != 1 ||
		naspolicyevidence.Inspect(installation, confirmed, nil, nil, true) != naspolicyevidence.NoRecordedOperation {
		return ErrInvalid
	}
	resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
	openDirectory := &unix.OpenHow{Flags: unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: resolve}
	// A new open description gives concurrent calls independent flock ownership.
	dir, err := unix.Openat2(int(parent.Fd()), ".", openDirectory)
	if err != nil {
		return ErrUnsafe
	}
	defer func() {
		if unix.Close(dir) != nil {
			result = errors.Join(result, ErrReview)
		}
	}()
	var info unix.Stat_t
	if unix.Fstat(dir, &info) != nil || info.Mode != unix.S_IFDIR|0700 || info.Uid != uint32(os.Geteuid()) {
		return ErrUnsafe
	}
	if err := unix.Flock(dir, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		if errors.Is(err, unix.EWOULDBLOCK) {
			return ErrBusy
		}
		return ErrUnsafe
	}
	if err := unix.Fstatat(dir, initialStageName, &info, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT); !errors.Is(err, unix.ENOENT) {
		return ErrReview
	}
	if err := unix.Fstatat(dir, initialPolicyName, &info, unix.AT_SYMLINK_NOFOLLOW|unix.AT_NO_AUTOMOUNT); !errors.Is(err, unix.ENOENT) {
		return ErrConflict
	}
	if err := unix.Mkdirat(dir, initialStageName, 0700); err != nil {
		return ErrReview
	}
	stage, err := unix.Openat2(dir, initialStageName, openDirectory)
	if err != nil {
		return ErrReview
	}
	header := []byte(fmt.Sprintf(`{"format":"phantowd-nas-evidence-container","schema_version":1,"installation_id":"%s"}`, installation))
	err = unix.Fchmod(stage, 0700)
	if err == nil {
		err = writeInitialRole(stage, "nas-evidence.json", header)
	}
	if err == nil {
		err = writeInitialRole(stage, "nas-services.json", confirmed)
	}
	if err == nil {
		err = unix.Fsync(stage)
	}
	if closeErr := unix.Close(stage); err != nil || closeErr != nil {
		return ErrReview
	}
	if unix.Renameat2(dir, initialStageName, dir, initialPolicyName, unix.RENAME_NOREPLACE) != nil ||
		unix.Fsync(dir) != nil {
		return ErrReview
	}
	return nil
}

func writeInitialRole(dir int, name string, data []byte) error {
	fd, err := unix.Openat(dir, name, unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	err = file.Chmod(0600)
	if err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	return errors.Join(err, file.Close())
}
