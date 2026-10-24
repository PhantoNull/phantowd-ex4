//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package nfskernel

import "golang.org/x/sys/unix"

// Private observation, not an execution/close authority or atomic FD lease.
type nfsSocketIdentityQEMU struct {
	device, inode, cookie uint64
}

func readNFSSocketIdentityQEMU(fd int) (nfsSocketIdentityQEMU, error) {
	var before, after unix.Stat_t
	var fs unix.Statfs_t
	if fd < 0 || unix.Fstat(fd, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		before.Ino == 0 || unix.Fstatfs(fd, &fs) != nil || fs.Type != 0x534f434b {
		return nfsSocketIdentityQEMU{}, ErrRefused
	}
	for _, option := range []struct{ key, value int }{
		{unix.SO_DOMAIN, unix.AF_INET}, {unix.SO_TYPE, unix.SOCK_STREAM}, {unix.SO_PROTOCOL, unix.IPPROTO_TCP},
	} {
		if value, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option.key); err != nil || value != option.value {
			return nfsSocketIdentityQEMU{}, ErrRefused
		}
	}
	flags, flagErr := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
	cookie, cookieErr := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	if flagErr != nil || flags&unix.FD_CLOEXEC == 0 || cookieErr != nil || cookie == 0 ||
		unix.Fstat(fd, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Mode != after.Mode {
		return nfsSocketIdentityQEMU{}, ErrRefused
	}
	return nfsSocketIdentityQEMU{uint64(before.Dev), before.Ino, cookie}, nil
}

func matchesNFSSocketIdentityQEMU(fd int, original nfsSocketIdentityQEMU) bool {
	if original.inode == 0 || original.cookie == 0 {
		return false
	}
	current, err := readNFSSocketIdentityQEMU(fd)
	return err == nil && current == original
}

func checkNFSSocketQEMU(fd int, original nfsSocketIdentityQEMU) error {
	if !matchesNFSSocketIdentityQEMU(fd, original) {
		return ErrRefused
	}
	address, err := unix.Getsockname(fd)
	ipv4, ok := address.(*unix.SockaddrInet4)
	accepting, acceptErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || !ok || ipv4.Port != 2049 || ipv4.Addr != [4]byte{127, 0, 0, 1} || acceptErr != nil || accepting != 1 ||
		!matchesNFSSocketIdentityQEMU(fd, original) {
		return ErrRefused
	}
	return nil
}
