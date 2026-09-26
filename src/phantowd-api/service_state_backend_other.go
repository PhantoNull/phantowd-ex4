//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func openDevelopmentServiceState(directory string) (*serviceStateBackend, func() error, error) {
	if directory == "" {
		return nil, func() error { return nil }, nil
	}
	return nil, nil, errors.New("writable service state requires Linux QEMU development build")
}
