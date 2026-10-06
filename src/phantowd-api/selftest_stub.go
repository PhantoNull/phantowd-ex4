//go:build !qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func runSelfTest() error {
	return errors.New("self-test harness is available only in the QEMU development build")
}

func runQEMUNFSTest(string) error {
	return errors.New("NFS fixture is available only in the QEMU development build")
}
