//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func runQEMUSMBTest() error { return errors.New("SMB integration fixture requires Linux ARMv5 QEMU") }

func runQEMUIdentityClient(string) error {
	return errors.New("identity client fixture requires Linux ARMv5 QEMU")
}

func runQEMUMountGuardTest() error {
	return errors.New("mount guard fixture requires Linux ARMv5 QEMU")
}
