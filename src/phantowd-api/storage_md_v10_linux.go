//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"io/fs"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mdmetadata"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

type mdV10GPTSetObserver func(
	context.Context,
	[]volumeprobe.BlockDeviceSource,
) ([]volumeprobe.Result, error)

// observeTrustedMDV10With is an internal read-only provider for the eventual
// storage owner. It performs complete discovery, GPT-to-sysfs correlation,
// bounded metadata reads, and a second inventory/mount/swap check. It does not
// expose data through HTTP or assemble, mount, import, repair or mutate media.
// A bounded block read can still wait on uninterruptible kernel I/O; context
// cancellation is checked between reads, not used as a claim of I/O revocation.
func observeTrustedMDV10With(
	ctx context.Context,
	sysfs, proc fs.FS,
	open storageSourceOpener,
	inspect mdV10PartitionInspector,
) (trustedMDV10Observation, error) {
	return observeTrustedMDV10WithObservers(ctx, sysfs, proc, open,
		observeTrustedMDV10GPTSet, inspect)
}

// observeTrustedMDV10WithObservers keeps the GPT probe behind the same
// in-process trust boundary as the block opener and MD parser. The alternate
// observer is a test seam for exercising post-observation race/failure paths;
// product code must call observeTrustedMDV10With, which binds the fixed
// volume-probe implementation.
func observeTrustedMDV10WithObservers(
	ctx context.Context,
	sysfs, proc fs.FS,
	open storageSourceOpener,
	observeGPT mdV10GPTSetObserver,
	inspect mdV10PartitionInspector,
) (trustedMDV10Observation, error) {
	if ctx == nil || ctx.Err() != nil || open == nil || observeGPT == nil || inspect == nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	discovery, err := discoverTrustedStorageWith(sysfs, proc, open)
	if err != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	defer discovery.Close()
	if len(discovery.candidates) > storageMDV10MaximumDisks || len(discovery.sources) != len(discovery.candidates) {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	gptResults, err := observeGPT(ctx, discovery.sources)
	if err != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	currentStorage, err := revalidateTrustedStorageDiscovery(sysfs, proc, discovery)
	if err != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	identities, err := observeCandidateGPTIdentities(discovery, currentStorage, gptResults)
	if err != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	observed, err := inspectTrustedMDV10Candidates(ctx, discovery, identities, inspect)
	if err != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	if _, err := revalidateTrustedStorageDiscovery(sysfs, proc, discovery); err != nil || ctx.Err() != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	if err := discovery.Close(); err != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	return observed, nil
}

func observeTrustedMDV10GPTSet(
	ctx context.Context,
	sources []volumeprobe.BlockDeviceSource,
) ([]volumeprobe.Result, error) {
	observed, err := volumeprobe.ObserveGPTBlockSet(ctx, sources)
	if err != nil {
		return nil, err
	}
	return observed.Results(), nil
}

var _ mdV10PartitionInspector = mdmetadata.InspectBlock
