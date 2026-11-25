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
	identity, err := takeStartupFile(4, unix.S_IFREG)
	if err != nil {
		return tls.Certificate{}, errTLSIdentity
	}
	pair, err := readTLSIdentity(identity, 0)
	if closeErr := identity.Close(); err != nil || closeErr != nil {
		return tls.Certificate{}, errTLSIdentity
	}
	return pair, nil
}

// The supervisor grants one private certificate/key generation. ReadAt leaves
// the original open-file-description offset alone if the supervisor retained it.
func readTLSIdentity(identity *os.File, owner uint32) (tls.Certificate, error) {
	bundle, _, err := readPrivateStartupFile(identity, owner, maxTLSIdentityBytes)
	if err != nil {
		return tls.Certificate{}, errTLSIdentity
	}
	defer clear(bundle)
	pair, err := tls.X509KeyPair(bundle, bundle)
	if err != nil {
		return tls.Certificate{}, errTLSIdentity
	}
	return pair, nil
}
