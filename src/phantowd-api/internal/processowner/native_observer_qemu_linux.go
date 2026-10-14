//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// Private endpoint retention, not a producer/channel or execution lease.
type nativeObserverSenderQEMU struct {
	device, inode, cookie uint64
	mode, uid, gid        uint32
	peer                  unix.Ucred
	passsecUnavailable    bool
}

func snapshotNativeObserverSenderQEMU(file *os.File) (nativeObserverSenderQEMU, error) {
	if file == nil {
		return nativeObserverSenderQEMU{}, ErrInvalid
	}
	raw, err := file.SyscallConn()
	if err != nil {
		return nativeObserverSenderQEMU{}, ErrInvalid
	}
	var result nativeObserverSenderQEMU
	var observedErr error
	err = raw.Control(func(value uintptr) {
		fd := int(value)
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK ||
			stat.Uid != uint32(os.Geteuid()) || stat.Gid != uint32(os.Getegid()) {
			observedErr = ErrInvalid
			return
		}
		descriptor, descriptorErr := unix.FcntlInt(value, unix.F_GETFD, 0)
		flags, flagsErr := unix.FcntlInt(value, unix.F_GETFL, 0)
		if descriptorErr != nil || flagsErr != nil || descriptor != unix.FD_CLOEXEC || flags != unix.O_RDWR {
			observedErr = ErrInvalid
			return
		}
		for _, option := range []struct{ name, value int }{
			{unix.SO_DOMAIN, unix.AF_UNIX}, {unix.SO_TYPE, unix.SOCK_SEQPACKET},
			{unix.SO_PROTOCOL, 0}, {unix.SO_PASSCRED, 0}, {unix.SO_PASSPIDFD, 0},
		} {
			got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option.name)
			if err != nil || got != option.value {
				observedErr = ErrInvalid
				return
			}
		}
		security, securityErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSSEC)
		unavailable := errors.Is(securityErr, unix.EOPNOTSUPP)
		if (securityErr != nil && !unavailable) || (!unavailable && security != 0) {
			observedErr = ErrInvalid
			return
		}
		cookie, cookieErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
		peer, peerErr := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
		creator := unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())}
		if cookieErr != nil || peerErr != nil || cookie == 0 || peer == nil || *peer != creator {
			observedErr = ErrInvalid
			return
		}
		result = nativeObserverSenderQEMU{device: uint64(stat.Dev), inode: uint64(stat.Ino),
			mode: stat.Mode, uid: stat.Uid, gid: stat.Gid, cookie: cookie,
			peer: *peer, passsecUnavailable: unavailable}
	})
	if err != nil || observedErr != nil {
		return nativeObserverSenderQEMU{}, ErrInvalid
	}
	return result, nil
}

func duplicateNativeObserverSenderQEMU(source *os.File) (*os.File, nativeObserverSenderQEMU, error) {
	identity, err := snapshotNativeObserverSenderQEMU(source)
	if err != nil {
		return nil, nativeObserverSenderQEMU{}, err
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, nativeObserverSenderQEMU{}, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	err = raw.Control(func(value uintptr) {
		fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil || duplicateErr != nil || fd < 0 {
		return nil, nativeObserverSenderQEMU{}, ErrInvalid
	}
	pin := os.NewFile(uintptr(fd), "original-observer-sender")
	duplicate, err := snapshotNativeObserverSenderQEMU(pin)
	final, finalErr := snapshotNativeObserverSenderQEMU(source)
	if err != nil || finalErr != nil || duplicate != identity || final != identity {
		closeErr := pin.Close()
		if closeErr != nil {
			return pin, nativeObserverSenderQEMU{}, errors.Join(ErrReviewRequired, closeErr)
		}
		return nil, nativeObserverSenderQEMU{}, ErrInvalid
	}
	return pin, identity, nil
}
