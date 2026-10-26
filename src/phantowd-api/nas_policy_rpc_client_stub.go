//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func runQEMUNASPolicyClient(string) error {
	return errors.New("NAS policy client fixture requires Linux QEMU")
}
