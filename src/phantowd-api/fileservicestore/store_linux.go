// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package fileservicestore atomically stores combined desired SMB/NFS policy.
// It does not provision state directories, migrate legacy policy or activate
// services. The HTTP management service does not open this store yet.
package fileservicestore

import (
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

type Store = revisionstore.Store[fileservice.Config]

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

// Open requires a separately provisioned private local directory. One complete
// revision is published with one rename, followed by directory sync. Errors
// and uncertainty have exactly the same meaning as the share-only store.
func Open(directory string) (*Store, error) {
	return revisionstore.OpenWithCodec(directory, revisionstore.Codec[fileservice.Config]{
		CurrentName: "file-services.json", PendingName: ".file-services.pending",
		MaxBytes: fileservice.MaxConfigBytes, Decode: fileservice.DecodeConfig, Validate: fileservice.Config.Validate,
		Revision: func(c fileservice.Config) uint64 { return c.Revision },
	})
}
