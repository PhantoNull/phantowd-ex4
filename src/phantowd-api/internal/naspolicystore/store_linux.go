//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package naspolicystore stores desired SMB/NFS/iSCSI as one revision.
// State provisioning, migration, credentials and activation remain separate.
package naspolicystore

import (
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

type Store = revisionstore.Store[naspolicy.Config]

var (
	ErrNotInitialized = revisionstore.ErrNotInitialized
	ErrConflict       = revisionstore.ErrConflict
	ErrInvalid        = revisionstore.ErrInvalid
	ErrUnsafe         = revisionstore.ErrUnsafe
	ErrBusy           = revisionstore.ErrBusy
	ErrUncertain      = revisionstore.ErrUncertain
)

// Open requires a separately provisioned private directory and holds its
// exclusive lock. No independent SMB/NFS/iSCSI writers or implicit import.
func Open(directory string) (*Store, error) {
	return revisionstore.OpenWithCodec(directory, revisionstore.Codec[naspolicy.Config]{
		CurrentName: "nas-services.json", PendingName: ".nas-services.pending",
		MaxBytes: naspolicy.MaxInputBytes, Decode: naspolicy.Decode, Validate: naspolicy.Config.Validate,
		Revision: func(c naspolicy.Config) uint64 { return c.Revision },
	})
}
