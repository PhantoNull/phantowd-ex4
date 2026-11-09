// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// OpenWriter borrows a separately provisioned trusted directory descriptor.
// The store retains its own descriptor and exclusive lock, which excludes the
// protected Reader. Opening neither initializes claims nor adopts a volume.
// Successful commits persist desired identity claims, not storage authority.
func OpenWriter(directory *os.File) (*revisionstore.Store[Document], error) {
	return revisionstore.OpenDirectoryWithCodec(directory, revisionstore.Codec[Document]{
		CurrentName: currentName, PendingName: ".volumes.pending", MaxBytes: MaxInputBytes,
		Decode: Decode, Validate: Document.Validate,
		Revision:           func(d Document) uint64 { return d.Revision },
		ValidateTransition: retainRegisteredIdentities,
	})
}

// Both documents have already passed the shared strict validator. Evaluate
// under the transaction lock, before any pending-file inspection or cleanup.
// An unavailable disk does not retire its ID or permit a different backing.
func retainRegisteredIdentities(current, next Document) error {
	expected := make(map[shareconfig.VolumeID]shareconfig.FilesystemUUID, len(next.Volumes))
	for _, claim := range next.Volumes {
		expected[claim.ID] = claim.FilesystemUUID
	}
	for _, claim := range current.Volumes {
		if uuid, exists := expected[claim.ID]; !exists || uuid != claim.FilesystemUUID {
			return ErrObservation
		}
	}
	return nil
}
