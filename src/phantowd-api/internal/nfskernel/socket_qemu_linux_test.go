//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package nfskernel

import (
	"testing"

	"golang.org/x/sys/unix"
)

func TestNFSSocketCheckRejectsSameEndpointReplacement(t *testing.T) {
	owned := map[int]bool{}
	t.Cleanup(func() {
		for fd := range owned {
			if err := unix.Close(fd); err != nil {
				t.Error("test-owned socket close failed", err)
			}
		}
	})
	newListener := func() (int, nfsSocketIdentityQEMU) {
		t.Helper()
		fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
		if err != nil {
			t.Fatal(err)
		}
		owned[fd] = true
		identity, err := readNFSSocketIdentityQEMU(fd)
		if err != nil {
			t.Fatal("fresh socket identity refused", err)
		}
		if unix.Bind(fd, &unix.SockaddrInet4{Port: 2049, Addr: [4]byte{127, 0, 0, 1}}) != nil || unix.Listen(fd, 1) != nil {
			t.Fatal("test loopback listener unavailable")
		}
		if err := checkNFSSocketQEMU(fd, identity); err != nil {
			t.Fatal("original socket refused after binding", err)
		}
		return fd, identity
	}
	originalFD, original := newListener()
	if err := unix.Close(originalFD); err != nil {
		t.Fatal(err)
	}
	delete(owned, originalFD)
	replacementFD, replacement := newListener()
	if original == replacement || original.cookie == replacement.cookie {
		t.Fatal("independent socket did not have distinct identity")
	}
	if checkNFSSocketQEMU(replacementFD, original) == nil {
		t.Fatal("same endpoint replacement admitted as original socket")
	}
	if checkNFSSocketQEMU(replacementFD, replacement) != nil {
		t.Fatal("refusal mutated the replacement socket")
	}
}

func TestNFSSocketIdentityRequiresOriginalTCPAndDescriptorFlags(t *testing.T) {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, unix.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	original, err := readNFSSocketIdentityQEMU(fd)
	if err != nil || !matchesNFSSocketIdentityQEMU(fd, original) {
		t.Fatal("fresh unbound socket identity refused", err)
	}
	if checkNFSSocketQEMU(fd, original) == nil {
		t.Fatal("identity observation incorrectly proved listening readiness")
	}
	for _, changed := range []nfsSocketIdentityQEMU{
		{}, {device: original.device, inode: original.inode},
		{device: original.device + 1, inode: original.inode, cookie: original.cookie},
		{device: original.device, inode: original.inode + 1, cookie: original.cookie},
		{device: original.device, inode: original.inode, cookie: original.cookie + 1},
	} {
		if matchesNFSSocketIdentityQEMU(fd, changed) {
			t.Fatal("incomplete or changed identity admitted")
		}
	}
	for _, invalid := range []int{-1} {
		if _, err := readNFSSocketIdentityQEMU(invalid); err == nil || matchesNFSSocketIdentityQEMU(invalid, original) {
			t.Fatal("invalid descriptor admitted")
		}
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); err != nil {
		t.Fatal(err)
	}
	if matchesNFSSocketIdentityQEMU(fd, original) {
		t.Fatal("descriptor flag change admitted")
	}
	if _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, unix.FD_CLOEXEC); err != nil || !matchesNFSSocketIdentityQEMU(fd, original) {
		t.Fatal("read-only flag observation modified socket identity", err)
	}
	for _, kind := range []struct{ family, socketType, protocol int }{
		{unix.AF_INET, unix.SOCK_DGRAM, unix.IPPROTO_UDP},
		{unix.AF_UNIX, unix.SOCK_STREAM, 0},
	} {
		other, err := unix.Socket(kind.family, kind.socketType|unix.SOCK_CLOEXEC, kind.protocol)
		if err != nil {
			t.Fatal(err)
		}
		_, observationErr := readNFSSocketIdentityQEMU(other)
		closeErr := unix.Close(other)
		if observationErr == nil || closeErr != nil {
			t.Fatal("foreign socket kind admitted or test closure failed", observationErr, closeErr)
		}
	}
	regular, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	_, observationErr := readNFSSocketIdentityQEMU(regular)
	closeErr := unix.Close(regular)
	if observationErr == nil || closeErr != nil {
		t.Fatal("non-socket admitted or test closure failed", observationErr, closeErr)
	}
}
