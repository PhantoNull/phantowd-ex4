//go:build qemu && !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func exerciseQEMUPolicyEvidenceFS() error {
	return errors.New("policy evidence filesystem fixture requires Linux")
}
