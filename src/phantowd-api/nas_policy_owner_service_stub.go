//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func runQEMUNASPolicyOwnerService() error {
	return errors.New("NAS policy provider boot is available only in the QEMU fixture")
}
