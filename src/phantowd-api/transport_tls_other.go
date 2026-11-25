//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/tls"
	"errors"
)

func loadInheritedTLSKeyPair() (tls.Certificate, error) {
	return tls.Certificate{}, errors.New("inherited TLS identity requires Linux")
}
