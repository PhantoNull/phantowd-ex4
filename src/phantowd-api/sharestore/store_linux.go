// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package sharestore stores validated desired share policy, never activation.
package sharestore

import (
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Store retains the original share-only format and filenames. It does not
// automatically migrate to the combined file-service policy store.
type Store = revisionstore.Store[shareconfig.Config]

var (
	ErrNotInitialized = revisionstore.ErrNotInitialized
	ErrConflict       = revisionstore.ErrConflict
	ErrInvalid        = revisionstore.ErrInvalid
	ErrUnsafe         = revisionstore.ErrUnsafe
	ErrBusy           = revisionstore.ErrBusy
	ErrIO             = revisionstore.ErrIO
	ErrUncertain      = revisionstore.ErrUncertain
	ErrClosed         = revisionstore.ErrClosed
)

// Open requires an existing private 0700 local directory under trusted parents.
// It retains an exclusive lock, validates/syncs existing state, and never
// initializes or promotes pending state. See README.md for the full contract.
func Open(directory string) (*Store, error) {
	return revisionstore.OpenWithCodec(directory, revisionstore.Codec[shareconfig.Config]{
		CurrentName: "shares.json", PendingName: ".shares.pending",
		MaxBytes: shareconfig.MaxInputBytes, Decode: shareconfig.Decode, Validate: shareconfig.Config.Validate,
		Revision: func(c shareconfig.Config) uint64 { return c.Revision },
	})
}
