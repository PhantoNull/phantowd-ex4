//go:build qemu && !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func exerciseQEMUShareStore() error {
	return errors.New("share-store self-test requires Linux")
}
