//go:build qemu && !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func exerciseQEMUSMBPreview() error {
	return errors.New("Samba preview self-test requires Linux and target testparm")
}
