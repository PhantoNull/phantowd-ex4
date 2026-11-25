//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfskernel

func ValidateProfileQEMU(threads, versions, ports []byte, running bool) error {
	return validateProfile(threads, versions, ports, running)
}
