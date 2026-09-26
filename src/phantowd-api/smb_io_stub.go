//go:build !qemu || !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func runQEMUSMBTest() error { return errors.New("SMB integration fixture requires Linux ARMv5 QEMU") }
