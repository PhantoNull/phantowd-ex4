// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package nfskernel coordinates an admitted Linux NFSD control lifetime.
package nfskernel

import (
	"bytes"
	"errors"
)

var ErrRefused = errors.New("NFS retained kernel control refused")

// validateProfile accepts only the selected kernel's exact v3-only
// profile. Legacy portlist does not identify listener address or family.
func validateProfile(threads, versions, ports []byte, running bool) error {
	wantThreads, wantPorts := "0\n", ""
	if running {
		wantThreads, wantPorts = "2\n", "tcp 2049\n"
	}
	if !bytes.Equal(threads, []byte(wantThreads)) || !bytes.Equal(versions, []byte("+3\n")) || !bytes.Equal(ports, []byte(wantPorts)) {
		return ErrRefused
	}
	return nil
}
