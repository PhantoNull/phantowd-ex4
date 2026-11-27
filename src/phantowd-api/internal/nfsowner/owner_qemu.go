//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"

// QEMUBackend is the trusted fixture backend for the memory-only lifetimes.
type QEMUBackend = serviceBackend

func NewQEMU(candidate fileserviceplan.NFSv3Candidate, backend QEMUBackend) (*Owner, error) {
	return newOwner(candidate, backend)
}
