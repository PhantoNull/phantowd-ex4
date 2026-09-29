// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"math"
	"path"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

type kernelPartitionBinding struct {
	KernelName string               `json:"-"`
	Major      uint32               `json:"-"`
	Minor      uint32               `json:"-"`
	Number     uint32               `json:"-"`
	Start512B  uint64               `json:"-"`
	Size512B   uint64               `json:"-"`
	TypeGUID   string               `json:"-"`
	TypeHint   gptPartitionTypeHint `json:"-"`
	UUID       string               `json:"-"`
	UUIDStatus string               `json:"-"`
}

const (
	partitionTableNoTable     = "no-partition-table"
	partitionTableGPT         = "gpt"
	partitionTableUnsupported = "unsupported"
)

type diskPartitionBinding struct {
	DiskName         string                            `json:"-"`
	Generation       volumeprobe.BlockDeviceGeneration `json:"-"`
	SourceStatus     string                            `json:"-"`
	TableDisposition string                            `json:"-"`
	Scheme           string                            `json:"-"`
	TableID          string                            `json:"-"`
	TableIDStatus    string                            `json:"-"`
	Partitions       []kernelPartitionBinding          `json:"-"`
}

// correlateDiskPartitionTable joins private helper output to one complete,
// collector-produced kernel inventory. A table entry is accepted only when
// the kernel has the exact partition child with the same number, start and
// size. The GPT type GUID is retained for a future explicit layout policy; this
// result is private metadata, not compatibility qualification or mount authority.
func correlateDiskPartitionTable(
	disk blockObservation,
	inventory []blockObservation,
	result volumeprobe.Result,
) (diskPartitionBinding, error) {
	if result.SourceKind != "block-device" || disk.Kind != "block" ||
		disk.diskSequence == 0 || disk.SizeBytes == 0 || disk.SizeBytes%linuxSysfsSectorBytes != 0 {
		return diskPartitionBinding{}, errStorageDiscoveryIncomplete
	}
	snapshot := storageSnapshot{
		SchemaVersion: 2, Scope: "kernel-sysfs-only", InventoryReadOnly: true,
		Observations: inventory, Limitations: []string{"internal trusted correlation"},
		DeviceCount: len(inventory), collectionComplete: true,
	}
	devices, err := completeObservedBlockDeviceSet(snapshot)
	if err != nil {
		return diskPartitionBinding{}, errStorageDiscoveryIncomplete
	}
	foundDisk := false
	for _, device := range devices {
		if device.Name == disk.Name && device.Generation == (volumeprobe.BlockDeviceGeneration{
			Major: disk.Major, Minor: disk.Minor, DiskSequence: disk.diskSequence,
		}) {
			foundDisk = true
			break
		}
	}
	if !foundDisk {
		return diskPartitionBinding{}, errStorageDiscoveryIncomplete
	}
	for _, observed := range inventory {
		if observed.Name == disk.Name && !sameBlockObservation(disk, observed) {
			return diskPartitionBinding{}, errStorageDiscoveryIncomplete
		}
	}

	kernelByNumber := make(map[uint32]blockObservation)
	for _, observed := range inventory {
		if observed.Kind != "partition" || observed.ParentName != disk.Name {
			continue
		}
		if observed.ParentMajor == nil || observed.ParentMinor == nil ||
			*observed.ParentMajor != disk.Major || *observed.ParentMinor != disk.Minor ||
			observed.parentDiskSeq != disk.diskSequence || path.Dir(observed.sysfsTarget) != disk.sysfsTarget ||
			observed.PartitionNumber == 0 || observed.partitionStart512B == 0 ||
			observed.SizeBytes == 0 || observed.SizeBytes%linuxSysfsSectorBytes != 0 {
			return diskPartitionBinding{}, errStorageDiscoveryIncomplete
		}
		if _, exists := kernelByNumber[observed.PartitionNumber]; exists {
			return diskPartitionBinding{}, errStorageDiscoveryIncomplete
		}
		kernelByNumber[observed.PartitionNumber] = observed
	}

	binding := diskPartitionBinding{
		DiskName: disk.Name,
		Generation: volumeprobe.BlockDeviceGeneration{
			Major: disk.Major, Minor: disk.Minor, DiskSequence: disk.diskSequence,
		},
		SourceStatus:     result.Status,
		TableDisposition: partitionTableNoTable,
		Partitions:       []kernelPartitionBinding{},
	}
	if result.Status == "unsupported-table" {
		// GPT-only observation deliberately discards MBR/DOS and no-table
		// identifiers. Current kernel partitions may still exist, so their
		// geometry is not used to invent stable IDs for an unsupported scheme.
		binding.TableDisposition = partitionTableUnsupported
		return binding, nil
	}
	if result.PartitionTable == nil {
		if len(kernelByNumber) != 0 {
			return diskPartitionBinding{}, errStorageDiscoveryIncomplete
		}
		return binding, nil
	}
	if result.Status != "other-signature" {
		return diskPartitionBinding{}, errStorageDiscoveryIncomplete
	}
	if result.PartitionTable.Scheme == "dos" {
		// DOS/MBR is intentionally not an identity source in this milestone.
		// Do not retain its disk signature, synthetic partition IDs, or entries.
		binding.TableDisposition = partitionTableUnsupported
		return binding, nil
	}
	if result.PartitionTable.Scheme != "gpt" || result.PartitionTable.ID == "" ||
		len(result.PartitionTable.Partitions) != len(kernelByNumber) {
		return diskPartitionBinding{}, errStorageDiscoveryIncomplete
	}
	binding.TableDisposition = partitionTableGPT
	binding.Scheme = result.PartitionTable.Scheme
	binding.TableID = result.PartitionTable.ID
	seenNumbers := make(map[uint32]bool, len(result.PartitionTable.Partitions))
	diskSectors := disk.SizeBytes / linuxSysfsSectorBytes
	for _, partition := range result.PartitionTable.Partitions {
		if partition.Number == 0 || partition.Start512B == 0 || partition.Size512B == 0 ||
			partition.Start512B > math.MaxUint64-partition.Size512B ||
			partition.Start512B+partition.Size512B > diskSectors || seenNumbers[partition.Number] {
			return diskPartitionBinding{}, errStorageDiscoveryIncomplete
		}
		seenNumbers[partition.Number] = true
		kernel, exists := kernelByNumber[partition.Number]
		if !exists || kernel.partitionStart512B != partition.Start512B ||
			kernel.SizeBytes/linuxSysfsSectorBytes != partition.Size512B {
			return diskPartitionBinding{}, errStorageDiscoveryIncomplete
		}
		binding.Partitions = append(binding.Partitions, kernelPartitionBinding{
			KernelName: kernel.Name, Major: kernel.Major, Minor: kernel.Minor,
			Number: partition.Number, Start512B: partition.Start512B,
			Size512B: partition.Size512B, TypeGUID: partition.TypeID,
			TypeHint: classifyGPTPartitionTypeGUID(partition.TypeID), UUID: partition.UUID,
		})
	}
	if len(seenNumbers) != len(kernelByNumber) {
		return diskPartitionBinding{}, errStorageDiscoveryIncomplete
	}
	return binding, nil
}

// correlateCandidatePartitionTables requires a one-to-one result/source entry
// for the entire currently eligible candidate set. It returns no partial
// bindings if the inventory, eligibility plan, generation or any table fails.
func correlateCandidatePartitionTables(
	discovery *trustedStorageDiscovery,
	current storageSnapshot,
	results []volumeprobe.Result,
) ([]diskPartitionBinding, error) {
	if discovery == nil || discovery.closed || discovery.inventory.Observations == nil ||
		!sameStorageSnapshot(discovery.inventory, current) ||
		len(discovery.candidates) != len(discovery.sources) ||
		len(results) != len(discovery.candidates) {
		return nil, errStorageDiscoveryIncomplete
	}
	devices, err := completeObservedBlockDeviceSet(current)
	if err != nil {
		return nil, errStorageDiscoveryIncomplete
	}
	plan, err := planTrustedStorageDiscovery(current, discovery.mounts)
	if err != nil || !sameStorageDiscoveryPlan(plan, discovery) {
		return nil, errStorageDiscoveryIncomplete
	}
	observations := make(map[string]blockObservation, len(current.Observations))
	devicesByName := make(map[string]volumeprobe.BlockDeviceGeneration, len(devices))
	for _, device := range devices {
		devicesByName[device.Name] = device.Generation
	}
	for _, observation := range current.Observations {
		observations[observation.Name] = observation
	}
	bindings := make([]diskPartitionBinding, 0, len(discovery.candidates))
	seenNames := make(map[string]bool, len(discovery.candidates))
	for index, candidate := range discovery.candidates {
		source := discovery.sources[index]
		generation, exists := devicesByName[candidate.Name]
		if source.File == nil || source.Generation != candidate.Generation ||
			!exists || generation != candidate.Generation ||
			seenNames[candidate.Name] {
			return nil, errStorageDiscoveryIncomplete
		}
		seenNames[candidate.Name] = true
		disk, exists := observations[candidate.Name]
		if !exists {
			return nil, errStorageDiscoveryIncomplete
		}
		binding, err := correlateDiskPartitionTable(disk, current.Observations, results[index])
		if err != nil {
			return nil, errStorageDiscoveryIncomplete
		}
		bindings = append(bindings, binding)
	}
	return bindings, nil
}

func sameStorageDiscoveryPlan(plan storageDiscoveryPlan, discovery *trustedStorageDiscovery) bool {
	if len(plan.Candidates) != len(discovery.candidates) ||
		len(plan.Excluded) != len(discovery.excluded) ||
		plan.HasAmbiguousIdentity != discovery.hasAmbiguousIdentity ||
		plan.IdentityEvidenceIncomplete != discovery.identityEvidenceIncomplete {
		return false
	}
	for index := range plan.Candidates {
		if plan.Candidates[index] != discovery.candidates[index] {
			return false
		}
	}
	for index := range plan.Excluded {
		if plan.Excluded[index] != discovery.excluded[index] {
			return false
		}
	}
	return true
}
