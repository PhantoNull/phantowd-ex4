//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func runQEMUIdentityOwnerService() error {
	return errors.New("identity owner service is available only in the QEMU development image")
}
