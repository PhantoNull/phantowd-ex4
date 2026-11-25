// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/tls"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

const maxTLSIdentityBytes = 128 * 1024

var errTLSIdentity = errors.New("inherited TLS identity unavailable or unsafe")

func loadInheritedTLSKeyPair() (tls.Certificate, error) {
	const descriptor = 4
	flags, err := unix.FcntlInt(descriptor, unix.F_GETFD, 0)
	var info unix.Stat_t
	if err != nil || flags&unix.FD_CLOEXEC != 0 || unix.Fstat(descriptor, &info) != nil ||
		info.Mode&unix.S_IFMT != unix.S_IFREG {
		return tls.Certificate{}, errTLSIdentity
	}
	identity := os.NewFile(descriptor, "inherited-tls-identity")
	pair, err := readTLSIdentity(identity, 0)
	if closeErr := identity.Close(); err != nil || closeErr != nil {
		return tls.Certificate{}, errTLSIdentity
	}
	return pair, nil
}

// The supervisor grants one private certificate/key generation. ReadAt leaves
// the original open-file-description offset alone if the supervisor retained it.
func readTLSIdentity(identity *os.File, owner uint32) (tls.Certificate, error) {
	flags, err := unix.FcntlInt(identity.Fd(), unix.F_GETFL, 0)
	var before, after unix.Stat_t
	if err != nil || flags&(unix.O_ACCMODE|unix.O_PATH) != unix.O_RDONLY ||
		unix.Fstat(int(identity.Fd()), &before) != nil || before.Uid != owner || before.Nlink != 1 ||
		(before.Mode != unix.S_IFREG|0400 && before.Mode != unix.S_IFREG|0600) ||
		before.Size < 1 || before.Size > maxTLSIdentityBytes {
		return tls.Certificate{}, errTLSIdentity
	}
	bundle := make([]byte, before.Size)
	defer clear(bundle)
	if _, err := identity.ReadAt(bundle, 0); err != nil || unix.Fstat(int(identity.Fd()), &after) != nil {
		return tls.Certificate{}, errTLSIdentity
	}
	after.Atim = before.Atim
	if after != before {
		return tls.Certificate{}, errTLSIdentity
	}
	pair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return tls.Certificate{}, errTLSIdentity
	}
	return pair, nil
}
