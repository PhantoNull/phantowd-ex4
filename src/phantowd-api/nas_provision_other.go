//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func provisionInheritedNASPolicy(string) error {
	return errors.New("NAS policy provisioning requires Linux")
}
