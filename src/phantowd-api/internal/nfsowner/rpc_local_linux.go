// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"net"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const (
	rpcLocalSocket = "rpcbind.sock"
	rpcLocalLock   = "rpcbind.lock"
	rpcLocalPath   = "/run/" + rpcLocalSocket
	rpcLocalMask   = unix.STATX_TYPE | unix.STATX_MODE | unix.STATX_UID | unix.STATX_GID |
		unix.STATX_INO | unix.STATX_NLINK | unix.STATX_MNT_ID_UNIQUE
)

// rpcLocal borrows the original runtime directory through RPC.Close. All
// operations run under the original RPC gate in the admitted namespace.
type rpcLocal struct {
	state  *runtimeState
	legacy bool
	socket *os.File
}

func (l *rpcLocal) parent() (int, uint64, error) {
	if err := l.state.checkRun(); err != nil {
		return -1, 0, err
	}
	fd := int(l.state.run.Fd())
	var held, alias unix.Statx_t
	const mask = unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	// rpcbind opens its lock via /var/run. Both userspace paths must
	// resolve to this exact admitted tmpfs directory.
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH, mask, &held) != nil ||
		unix.Statx(unix.AT_FDCWD, "/var/run", 0, mask, &alias) != nil ||
		held.Mask&mask != mask || alias.Mask&mask != mask || held.Ino != alias.Ino ||
		held.Mnt_id != alias.Mnt_id {
		return -1, 0, ErrState
	}
	return fd, held.Mnt_id, nil
}

func (l *rpcLocal) requireAbsent() error {
	fd, _, err := l.parent()
	if err != nil {
		return err
	}
	for _, name := range []string{rpcLocalSocket, rpcLocalLock} {
		var info unix.Statx_t
		if err := unix.Statx(fd, name, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_TYPE, &info); !errors.Is(err, unix.ENOENT) {
			return errors.Join(ErrState, err)
		}
	}
	return nil
}

func (l *rpcLocal) pin(ctx context.Context, pid int) error {
	fd, _, err := l.parent()
	if err != nil {
		return err
	}
	opened, err := unix.Openat2(fd, rpcLocalSocket, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS,
	})
	if err != nil {
		return err
	}
	// Keep the descriptor even on a failed check for review and teardown.
	l.socket = os.NewFile(uintptr(opened), "managed-rpcbind-socket")
	return l.check(ctx, pid)
}

func (l *rpcLocal) check(ctx context.Context, pid int) error {
	if l.socket == nil || pid <= 0 {
		return ErrState
	}
	if err := l.checkPaths(); err != nil {
		return err
	}
	if err := checkRPCBindPeer(ctx, pid); err != nil {
		return err
	}
	return l.checkPaths()
}

func (l *rpcLocal) checkPaths() error {
	fd, mount, err := l.parent()
	if err != nil {
		return err
	}
	var held, name, lock unix.Statx_t
	if unix.Statx(int(l.socket.Fd()), "", unix.AT_EMPTY_PATH, rpcLocalMask, &held) != nil ||
		unix.Statx(fd, rpcLocalSocket, unix.AT_SYMLINK_NOFOLLOW, rpcLocalMask, &name) != nil ||
		unix.Statx(fd, rpcLocalLock, unix.AT_SYMLINK_NOFOLLOW, rpcLocalMask, &lock) != nil {
		return ErrState
	}
	mode := uint16(unix.S_IFSOCK | 0600)
	if l.legacy && held.Mode == unix.S_IFSOCK|0666 {
		mode = unix.S_IFSOCK | 0666
	}
	if !validRPCNode(held, mount, mode) || !validRPCNode(name, mount, mode) ||
		name.Ino != held.Ino || !validRPCNode(lock, mount, unix.S_IFREG|0444) {
		return ErrState
	}
	return nil
}

func validRPCNode(info unix.Statx_t, mount uint64, mode uint16) bool {
	return info.Mask&rpcLocalMask == rpcLocalMask && info.Mnt_id == mount &&
		info.Ino != 0 && info.Mode == mode && info.Uid == 0 && info.Gid == 0 && info.Nlink == 1
}

func checkRPCBindPeer(ctx context.Context, pid int) (result error) {
	conn, err := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", rpcLocalPath)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, conn.Close()) }()
	raw, err := conn.(*net.UnixConn).SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var peerErr error
	if err := raw.Control(func(fd uintptr) {
		cred, peerErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return err
	}
	if peerErr != nil || cred == nil || int(cred.Pid) != pid || cred.Uid != 0 || cred.Gid != 0 {
		return errors.Join(ErrState, peerErr)
	}
	return ctx.Err()
}
