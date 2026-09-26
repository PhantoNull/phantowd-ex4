//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func openAccountBackend(string) (accountBackend, error) {
	return nil, errors.New("durable administrator state requires Linux")
}
