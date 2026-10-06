// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"io/fs"
	"math"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mdmetadata"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

const (
	storageMDV10MaximumDisks      = 4
	storageMDV10MaximumPartitions = 128
)

type mdV10PartitionInspector func(
	source *os.File,
	generation volumeprobe.BlockDeviceGeneration,
	sourceBytes uint64,
	partition mdmetadata.Partition,
) (mdmetadata.Observation, error)

// trustedMDV10Observation is an internal metadata-only result. Its comparison
// is scoped to complete trusted discovery plus GPT-declared Linux RAID member
// partitions; it is not WD compatibility, array health or mount authority.
type trustedMDV10Observation struct {
	CandidateDiskCount int
	GPTDiskCount       int
	RAIDPartitionCount int
	Comparison         mdmetadata.SetComparison
}

// inspectTrustedMDV10Candidates reads only partitions whose validated GPT type
// is Linux RAID member. discovery and identities must come from
// discoverTrustedStorageWith and observeCandidateGPTIdentities respectively.
// The injected inspector keeps the selection contract host-testable; the live
// caller supplies mdmetadata.InspectBlock, which enforces O_RDONLY and checks
// major/minor, diskseq, device size and logical sector size around each read.
func inspectTrustedMDV10Candidates(
	ctx context.Context,
	discovery *trustedStorageDiscovery,
	identities gptIdentitySetObservation,
	inspect mdV10PartitionInspector,
) (trustedMDV10Observation, error) {
	if ctx == nil || ctx.Err() != nil || discovery == nil || discovery.closed || inspect == nil ||
		discovery.inventory.Observations == nil || !discovery.inventory.collectionComplete ||
		discovery.inventory.SchemaVersion != 2 || len(discovery.candidates) == 0 ||
		len(discovery.candidates) > storageMDV10MaximumDisks ||
		len(discovery.sources) != len(discovery.candidates) ||
		identities.CandidateCount != len(discovery.candidates) ||
		identities.GPTDiskCount != len(discovery.candidates) ||
		identities.Coverage != gptIdentityCoverageAllCandidates ||
		len(identities.Bindings) != len(discovery.candidates) {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}

	disks := make(map[string]blockObservation, len(discovery.inventory.Observations))
	for _, observation := range discovery.inventory.Observations {
		if observation.Name == "" {
			return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
		}
		if observation.Kind == "block" {
			if _, exists := disks[observation.Name]; exists {
				return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
			}
			disks[observation.Name] = observation
		}
	}

	components := make([]mdmetadata.ComponentEvidence, 0)
	result := trustedMDV10Observation{
		CandidateDiskCount: len(discovery.candidates),
		GPTDiskCount:       identities.GPTDiskCount,
	}
	for diskIndex, candidate := range discovery.candidates {
		if err := ctx.Err(); err != nil {
			return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
		}
		source := discovery.sources[diskIndex]
		binding := identities.Bindings[diskIndex]
		disk, exists := disks[candidate.Name]
		if !exists || source.File == nil || source.Generation != candidate.Generation ||
			binding.DiskName != candidate.Name || binding.Generation != candidate.Generation ||
			binding.TableDisposition != partitionTableGPT || binding.Scheme != "gpt" ||
			!validCanonicalGPTGUID(binding.TableID) || len(binding.Partitions) > storageMDV10MaximumPartitions ||
			disk.Major != candidate.Generation.Major || disk.Minor != candidate.Generation.Minor ||
			disk.diskSequence != candidate.Generation.DiskSequence || disk.SizeBytes == 0 ||
			disk.SizeBytes%linuxSysfsSectorBytes != 0 {
			return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
		}
		seenNumbers := make(map[uint32]bool, len(binding.Partitions))
		for _, partition := range binding.Partitions {
			if !validBlockName(partition.KernelName) || partition.Number == 0 ||
				partition.Number > storageMDV10MaximumPartitions || partition.Start512B == 0 ||
				partition.Size512B == 0 || partition.Start512B > math.MaxUint64-partition.Size512B ||
				partition.Start512B+partition.Size512B > disk.SizeBytes/linuxSysfsSectorBytes ||
				!validCanonicalGPTGUID(partition.TypeGUID) ||
				partition.TypeHint != classifyGPTPartitionTypeGUID(partition.TypeGUID) ||
				!validCanonicalGPTGUID(partition.UUID) || seenNumbers[partition.Number] {
				return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
			}
			seenNumbers[partition.Number] = true
			if partition.TypeHint != gptTypeHintLinuxRAID {
				continue
			}
			if err := ctx.Err(); err != nil {
				return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
			}
			observed, err := inspect(source.File, source.Generation, disk.SizeBytes, mdmetadata.Partition{
				Number: partition.Number, StartLBA: partition.Start512B, SizeLBA: partition.Size512B,
			})
			if err != nil || !mdV10ObservationMatchesPartition(observed, disk.SizeBytes, partition) {
				return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
			}
			components = append(components, mdmetadata.ComponentEvidence{
				DiskIndex: uint32(diskIndex + 1), PartitionNumber: partition.Number, Observation: observed,
			})
			result.RAIDPartitionCount++
		}
	}
	comparison, err := mdmetadata.CompareComponents(components)
	if err != nil {
		return trustedMDV10Observation{}, errStorageDiscoveryIncomplete
	}
	result.Comparison = comparison
	return result, nil
}

func mdV10ObservationMatchesPartition(
	observation mdmetadata.Observation,
	diskBytes uint64,
	partition kernelPartitionBinding,
) bool {
	if diskBytes == 0 || diskBytes%linuxSysfsSectorBytes != 0 || partition.Size512B == 0 ||
		partition.Start512B > math.MaxUint64-partition.Size512B ||
		partition.Size512B > math.MaxUint64/linuxSysfsSectorBytes {
		return false
	}
	return observation.PartitionNumber == partition.Number &&
		observation.PartitionFirstLBA == partition.Start512B &&
		observation.PartitionLastLBA == partition.Start512B+partition.Size512B-1 &&
		observation.DiskSectors == diskBytes/linuxSysfsSectorBytes &&
		observation.PartitionBytes == partition.Size512B*linuxSysfsSectorBytes
}

func revalidateTrustedStorageDiscovery(
	sysfs, proc fs.FS,
	discovery *trustedStorageDiscovery,
) (storageSnapshot, error) {
	if discovery == nil || discovery.closed {
		return storageSnapshot{}, errStorageDiscoveryIncomplete
	}
	currentStorage, err := collectStorage(sysfs)
	if err != nil || !sameStorageSnapshot(discovery.inventory, currentStorage) {
		return storageSnapshot{}, errStorageDiscoveryIncomplete
	}
	currentMounts, err := collectMountInventory(proc, time.Now())
	if err != nil || !sameMountSnapshot(discovery.mounts, currentMounts) {
		return storageSnapshot{}, errStorageDiscoveryIncomplete
	}
	currentSwap, err := collectSwapObservation(proc)
	if err != nil || currentSwap != discovery.swap || currentSwap.entries != 0 {
		return storageSnapshot{}, errStorageDiscoveryIncomplete
	}
	plan, err := planTrustedStorageDiscovery(currentStorage, currentMounts)
	if err != nil || !sameStorageDiscoveryPlan(plan, discovery) {
		return storageSnapshot{}, errStorageDiscoveryIncomplete
	}
	return currentStorage, nil
}
