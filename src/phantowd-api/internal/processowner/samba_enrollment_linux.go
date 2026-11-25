// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"golang.org/x/sys/unix"
)

// NewSambaEnrollmentCapture reserves one fixed image worker. FD 3 executes
// the retained API, FD 4 holds the configuration, and FD 5/6 are its original
// ext4 database directories. The sealed credential is inherited as stdin.
func NewSambaEnrollmentCapture(executable, input, configuration, private, state *os.File,
	operation, name string) (_ *CaptureOwner, result error) {
	if _, _, err := smbprovision.WorkerCommand(operation, name); err != nil ||
		smbprovision.VerifyWorkerInput(input, operation) != nil {
		return nil, ErrInvalid
	}
	var fs unix.Statfs_t
	if executable == nil || unix.Fstatfs(int(executable.Fd()), &fs) != nil || fs.Flags&unix.ST_RDONLY == 0 {
		return nil, ErrInvalid
	}
	capture, err := NewCapture(CaptureSpec{
		ExecutableLabel: "/usr/bin/phantowd-api",
		Args:            []string{"--run-rc0-samba-worker=" + operation, "--rc0-samba-account=" + name},
		RunAs:           &Credentials{UID: 0, GID: 0}, Timeout: 15 * time.Second, StopTimeout: time.Second,
	}, executable, input)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, capture.release())
		}
	}()
	var directory [3]sambaEnrollmentDirectory
	for i, file := range []*os.File{configuration, private, state} {
		if file == nil {
			return nil, ErrInvalid
		}
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		capture.fixtureInputs = append(capture.fixtureInputs, os.NewFile(uintptr(fd), "samba-enrollment-directory"))
		directory[i], err = observeEnrollmentDirectory(fd, i == 0)
		if err != nil {
			return nil, err
		}
	}
	if directory[1].mount != directory[2].mount || directory[1].inode == directory[2].inode {
		return nil, ErrInvalid
	}
	capture.fixtureInputsValid = func() bool {
		for i, file := range capture.fixtureInputs {
			observed, err := observeEnrollmentDirectory(int(file.Fd()), i == 0)
			if err != nil || observed != directory[i] {
				return false
			}
		}
		return true
	}
	capture.dieWithParent = true
	if operation == smbprovision.WorkerObserve {
		capture.stdoutLimit = 1 << 20
	}
	return capture, nil
}

type sambaEnrollmentDirectory struct{ mount, inode uint64 }

func observeEnrollmentDirectory(fd int, configuration bool) (sambaEnrollmentDirectory, error) {
	const mask = unix.STATX_MNT_ID_UNIQUE | unix.STATX_INO | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID | unix.STATX_TYPE
	var st unix.Statx_t
	var fs unix.Statfs_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &st) != nil || st.Mask&mask != mask ||
		st.Mnt_id == 0 || st.Uid != 0 || st.Gid != 0 || unix.Fstatfs(fd, &fs) != nil {
		return sambaEnrollmentDirectory{}, ErrInvalid
	}
	if configuration {
		const expected = unix.ST_RDONLY | unix.ST_NOEXEC | unix.ST_NODEV | unix.ST_NOSUID
		if st.Mode != unix.S_IFDIR|0755 || fs.Type != unix.TMPFS_MAGIC || fs.Flags&expected != expected {
			return sambaEnrollmentDirectory{}, ErrInvalid
		}
	} else if st.Mode != unix.S_IFDIR|0700 || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&unix.ST_RDONLY != 0 {
		return sambaEnrollmentDirectory{}, ErrInvalid
	}
	return sambaEnrollmentDirectory{mount: st.Mnt_id, inode: st.Ino}, nil
}
