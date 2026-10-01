//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mdmetadata"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

// observeTrustedMDV10ForBroker exists only in the disposable QEMU test build.
// Production firmware therefore returns unavailable for the fixed operation
// without opening or reading a real block device.
func observeTrustedMDV10ForBroker(ctx context.Context) (storageMDV10ObservationSummary, error) {
	if ctx == nil || ctx.Err() != nil {
		return storageMDV10ObservationSummary{}, errStorageDiscoveryIncomplete
	}
	principals, err := lookupStorageBrokerPrincipals()
	if err != nil || !validStorageBrokerCredentials(principals) {
		return storageMDV10ObservationSummary{}, errStorageBrokerUnavailable
	}
	opener := func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		return openBrokerReadOnlySources(devices, principals.deviceGID)
	}
	observation, err := observeTrustedMDV10With(ctx, os.DirFS("/sys"), os.DirFS("/proc"), opener,
		mdmetadata.InspectBlock)
	if err != nil {
		return storageMDV10ObservationSummary{}, errStorageDiscoveryIncomplete
	}
	return summarizeTrustedMDV10Observation(observation)
}

func validQEMUMDV10FixtureSummary(summary storageMDV10ObservationSummary) bool {
	return validStorageMDV10ObservationSummary(summary) &&
		summary.CandidateDiskCount == 2 && summary.GPTDiskCount == 2 && summary.RAIDPartitionCount == 2 &&
		summary.CandidateComponents == 2 && summary.UnqualifiedComponents == 0 &&
		summary.UnidentifiedCandidateComponents == 0 && summary.ArrayCount == 1 &&
		summary.MetadataConsistentArrayCount == 1 && summary.IncompleteArrayCount == 0 &&
		summary.DivergentEventArrayCount == 0 && summary.ConflictingArrayCount == 0 &&
		summary.AmbiguousArrayCount == 0 && summary.MetadataActiveRoleCoverageComplete &&
		summary.BlockMetadataRead && summary.MDV10SuperblocksRead && !summary.FilesystemDataRead &&
		!summary.AssemblyPerformed && !summary.MountPerformed && !summary.ImportPerformed && !summary.MutationsPerformed
}
