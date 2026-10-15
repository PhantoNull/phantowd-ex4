//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "os"

// Development portability only. Linux supplies the firmware's no-follow,
// nonblocking leaf-open semantics; portable metadata checks do not certify ACLs.
func openTLSMaterialFile(path string) (*os.File, error) { return os.Open(path) }
