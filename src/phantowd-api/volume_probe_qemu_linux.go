//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

// Fixed QEMU harness, not the production broker or arbitrary device opener.
func runProbeFixture(source *os.File) (volumeprobe.Result, error) {
	return volumeprobe.Inspect(context.Background(), source)
}

func probeQEMUUnmountedStorage() error {
	// The dispatcher already requires ARMv5 and exact Versatile PB model.
	if os.Geteuid() != 0 {
		return errors.New("QEMU probe requires fixture root")
	}
	if err := verifyQEMUNFSDevice(os.DirFS("/sys")); err != nil {
		return err
	}
	if err := verifyQEMUBlockDevice(os.DirFS("/sys"), "sdc", qemuCloneSerial, qemuCloneWWN); err != nil {
		return err
	}
	discovery, err := discoverTrustedStorageWith(os.DirFS("/sys"), os.DirFS("/proc"), volumeprobe.OpenObservedBlockSources)
	if err != nil {
		return errors.New("complete QEMU trusted storage discovery was unavailable")
	}
	defer discovery.Close()
	initialInventory := discovery.inventory
	if len(discovery.sources) != len(discovery.candidates) || len(discovery.candidates) < 2 {
		return errors.New("complete QEMU discovery did not return one source for every eligible candidate")
	}
	candidateByName := make(map[string]storageDiscoveryCandidate, len(discovery.candidates))
	sourceByName := make(map[string]volumeprobe.BlockDeviceSource, len(discovery.sources))
	candidateNames := make([]string, 0, len(discovery.candidates))
	for index, candidate := range discovery.candidates {
		if _, exists := candidateByName[candidate.Name]; exists || discovery.sources[index].File == nil ||
			discovery.sources[index].Generation != candidate.Generation {
			return errors.New("complete QEMU discovery returned a duplicate or mismatched candidate source")
		}
		candidateByName[candidate.Name] = candidate
		sourceByName[candidate.Name] = discovery.sources[index]
		candidateNames = append(candidateNames, candidate.Name)
	}
	if _, rootIsCandidate := candidateByName["sda"]; rootIsCandidate {
		return errors.New("complete QEMU discovery treated the mounted root disk as an eligible candidate")
	}
	observedDevices := make([]volumeprobe.ObservedBlockDevice, 0, 2)
	for _, name := range []string{"sdb", "sdc"} {
		candidate, exists := candidateByName[name]
		if !exists {
			return fmt.Errorf("complete QEMU discovery omitted unmounted clone-test disk %s; candidates=%v exclusions=%v", name, candidateNames, discovery.excluded)
		}
		observedDevices = append(observedDevices, volumeprobe.ObservedBlockDevice{
			Name: candidate.Name, Generation: candidate.Generation,
		})
	}
	deviceIDs := make(map[string]bool)
	for _, device := range observedDevices {
		deviceNumber := fmt.Sprintf("%d:%d", device.Generation.Major, device.Generation.Minor)
		deviceIDs[deviceNumber] = true
	}
	if len(deviceIDs) != 2 {
		return errors.New("fixture requires distinct virtual devices")
	}
	unmounted := func() error {
		currentInventory, err := collectStorage(os.DirFS("/sys"))
		if err != nil || !sameQEMUStorageInventory(initialInventory, currentInventory) {
			return errors.New("probe fixture storage topology changed")
		}
		mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
		if err != nil {
			return err
		}
		for _, device := range []string{"sdb", "sdc"} {
			var disk *blockObservation
			for index := range currentInventory.Observations {
				observation := &currentInventory.Observations[index]
				if observation.Name == device {
					disk = observation
					break
				}
			}
			if disk == nil {
				return errors.New("probe fixture disk disappeared from sysfs")
			}
			mounted, err := observedWholeDiskHasVisibleDependentMount(*disk, currentInventory.Observations, mounts.Mounts)
			if err != nil || mounted {
				return errors.New("probe fixture disk has a visible mount through an observed dependent node")
			}
		}
		return nil
	}
	if err := unmounted(); err != nil {
		return err
	}
	fdEntriesBefore, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	incompleteSources, err := volumeprobe.OpenObservedBlockSources([]volumeprobe.ObservedBlockDevice{
		observedDevices[0],
		{Name: "phantowd-missing-device", Generation: volumeprobe.BlockDeviceGeneration{Major: 255, Minor: 255, DiskSequence: ^uint64(0)}},
	})
	fdEntriesAfter, fdErr := os.ReadDir("/proc/self/fd")
	if !errors.Is(err, volumeprobe.ErrUnsafe) || incompleteSources != nil || fdErr != nil || len(fdEntriesBefore) != len(fdEntriesAfter) {
		return errors.New("incomplete QEMU source set leaked a descriptor or returned partial sources")
	}
	if err := volumeprobe.VerifyQEMUSymlinkRefusal(observedDevices[0]); err != nil {
		return errors.New("QEMU source opener followed a /dev symlink")
	}
	finalInventory, err := collectStorage(os.DirFS("/sys"))
	if err != nil || !sameQEMUStorageInventory(initialInventory, finalInventory) {
		return errors.New("QEMU sysfs inventory changed while opening the fixture source set")
	}
	blockSources := discovery.sources
	inventoryGenerations := make([]volumeprobe.BlockDeviceGeneration, len(discovery.candidates))
	shuffledSources := make([]volumeprobe.BlockDeviceSource, len(blockSources))
	for index, candidate := range discovery.candidates {
		inventoryGenerations[index] = candidate.Generation
		shuffledSources[len(shuffledSources)-1-index] = blockSources[index]
	}
	orderedSources, err := volumeprobe.OrderCompleteBlockSources(inventoryGenerations, shuffledSources)
	if err != nil || len(orderedSources) != len(discovery.candidates) {
		return errors.New("complete QEMU source set did not bind to sysfs inventory order")
	}
	for index, source := range orderedSources {
		if source.Generation != inventoryGenerations[index] || source.File != blockSources[index].File {
			return errors.New("shuffled QEMU sources were not restored to complete inventory order")
		}
	}
	snapshot, err := volumeprobe.ObserveBlockSet(context.Background(), orderedSources)
	if err != nil {
		return err
	}
	results := snapshot.Results()
	if len(results) != len(orderedSources) {
		return errors.New("incomplete virtual probe snapshot")
	}
	partitionInventory, err := collectStorage(os.DirFS("/sys"))
	if err != nil || !sameQEMUStorageInventory(initialInventory, partitionInventory) {
		return errors.New("QEMU inventory changed before partition-table correlation")
	}
	identityObservation, err := observeCandidateGPTIdentities(discovery, partitionInventory, results)
	if err != nil {
		return errors.New("complete QEMU parser-to-kernel partition correlation failed")
	}
	partitionBindings := identityObservation.Bindings
	correlatedGPTDisks := 0
	correlatedPartitions := 0
	mismatchRefused := false
	var qemuGPTBinding diskPartitionBinding
	for index, binding := range partitionBindings {
		if binding.TableDisposition == partitionTableGPT {
			correlatedGPTDisks++
			if binding.DiskName != "sdd" || binding.Scheme != "gpt" ||
				binding.TableID != "fedcba98-7654-3210-fedc-ba9876543210" ||
				len(binding.Partitions) != 1 || binding.Partitions[0].KernelName != "sdd1" ||
				binding.Partitions[0].Number != 1 || binding.Partitions[0].Start512B != 2048 ||
				binding.Partitions[0].Size512B != 63455 ||
				binding.Partitions[0].TypeGUID != "0fc63daf-8483-4772-8e79-3d69d8477de4" ||
				binding.TableIDStatus != gptIdentitySingletonObserved ||
				binding.Partitions[0].UUIDStatus != gptIdentitySingletonObserved {
				return errors.New("QEMU GPT partition did not match its exact kernel child geometry")
			}
			qemuGPTBinding = binding
			correlatedPartitions += len(binding.Partitions)
			if index >= len(results) || index >= len(discovery.candidates) {
				return errors.New("QEMU GPT result lost its complete candidate binding")
			}
			mismatchedResult := results[index]
			mismatchedTable := *mismatchedResult.PartitionTable
			mismatchedTable.Partitions = append([]volumeprobe.Partition(nil), mismatchedTable.Partitions...)
			mismatchedTable.Partitions[0].Start512B++
			mismatchedResult.PartitionTable = &mismatchedTable
			for _, observed := range partitionInventory.Observations {
				if observed.Name == discovery.candidates[index].Name {
					if _, err := correlateDiskPartitionTable(observed, partitionInventory.Observations, mismatchedResult); err == nil {
						return errors.New("QEMU accepted a GPT/sysfs partition start mismatch")
					}
					mismatchRefused = true
					break
				}
			}
		} else if binding.TableDisposition != partitionTableNoTable &&
			binding.TableDisposition != partitionTableUnsupported {
			return errors.New("QEMU partition table received an unknown private disposition")
		}
	}
	if correlatedGPTDisks != 1 || correlatedPartitions != 1 || !mismatchRefused ||
		identityObservation.CandidateCount != len(discovery.candidates) ||
		identityObservation.GPTDiskCount != 1 || identityObservation.Coverage != gptIdentityCoveragePartial {
		return errors.New("QEMU did not reconcile the complete candidate set's single GPT disk")
	}
	fmt.Println("PHANTOWD_PARTITION_SYSFS_CORRELATION_READY candidates_complete=true table_disks=1 partitions=1 start_size_match=true type_guid_preserved=true mismatch_refused=true scope=qemu-fixture-only")
	clone := qemuGPTBinding
	clone.DiskName = "sdg"
	clone.Generation = volumeprobe.BlockDeviceGeneration{Major: 65, Minor: 0, DiskSequence: 999}
	clone.Partitions = append([]kernelPartitionBinding(nil), qemuGPTBinding.Partitions...)
	clone.Partitions[0].KernelName = "sdg1"
	clone.Partitions[0].Major = 65
	clone.Partitions[0].Minor = 1
	clonedIdentityObservation, err := classifyGPTPartitionIdentities([]diskPartitionBinding{qemuGPTBinding, clone})
	if err != nil || clonedIdentityObservation.Bindings[0].TableIDStatus != gptIdentityAmbiguousObserved ||
		clonedIdentityObservation.Bindings[1].TableIDStatus != gptIdentityAmbiguousObserved ||
		clonedIdentityObservation.Bindings[0].Partitions[0].UUIDStatus != gptIdentityAmbiguousObserved ||
		clonedIdentityObservation.Bindings[1].Partitions[0].UUIDStatus != gptIdentityAmbiguousObserved {
		return errors.New("QEMU did not classify cloned GPT identifiers as ambiguous")
	}
	fmt.Println("PHANTOWD_PARTITION_IDENTITY_CLASSIFICATION_READY candidates_complete=true observed_gpt_disks=1 coverage=partial synthetic_clone_pair=2 duplicate_disk_guid=ambiguous duplicate_partuuid=ambiguous scope=qemu-fixture-only")
	resultByName := make(map[string]volumeprobe.Result, len(results))
	for index, candidate := range discovery.candidates {
		resultByName[candidate.Name] = results[index]
	}
	for _, name := range []string{"sdb", "sdc"} {
		result := resultByName[name]
		if result.Status != "ext-metadata" || result.SourceKind != "block-device" || result.Filesystem != "ext2" || result.FilesystemUUID != qemuNFSVolumeUUID {
			return errors.New("unmounted virtual metadata did not match")
		}
	}
	match, err := snapshot.MatchUUID(qemuNFSVolumeUUID)
	if err != nil || match.State != "conflicting-objects" || len(match.SourceIndices) != 2 {
		return errors.New("unmounted clone conflict missed")
	}
	dataSource := sourceByName["sdb"]
	alias, err := volumeprobe.ObserveBlockSet(context.Background(), []volumeprobe.BlockDeviceSource{dataSource, dataSource})
	if err != nil {
		return err
	}
	match, err = alias.MatchUUID(qemuNFSVolumeUUID)
	if err != nil || match.State != "one-object" || len(match.SourceIndices) != 2 {
		return errors.New("same block object mistaken for clone")
	}
	staleGeneration := dataSource
	staleGeneration.Generation.DiskSequence++
	stale, err := volumeprobe.ObserveBlockSet(context.Background(), []volumeprobe.BlockDeviceSource{staleGeneration})
	if !errors.Is(err, volumeprobe.ErrUnsafe) || len(stale.Results()) != 0 {
		return errors.New("stale block generation was accepted")
	}
	match, err = snapshot.MatchUUID("00112233-4455-6677-8899-aabbccddeeff")
	if err != nil || match.State != "not-observed" || len(match.SourceIndices) != 0 {
		return errors.New("unobserved UUID gained a match")
	}
	blank, err := os.CreateTemp("/run", "phantowd-probe-blank-")
	if err != nil {
		return err
	}
	name := blank.Name()
	defer os.Remove(name)
	if err := blank.Truncate(4096); err != nil {
		blank.Close()
		return err
	}
	blank.Close()
	blank, err = os.Open(name)
	if err != nil {
		return err
	}
	result, err := runProbeFixture(blank)
	blank.Close()
	if err != nil || result.Status != "unidentified" || result.SourceKind != "regular-image" || result.Filesystem != "" || result.FilesystemUUID != "" {
		return fmt.Errorf("unidentified regular-image fixture failed: %v", err)
	}
	if err := unmounted(); err != nil {
		return err
	}
	if err := probeQEMUSparseGPT(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_VOLUME_PROBE_READY backend=libblkid unmounted_devices=2 readonly_descriptors=true expected_uuid=true unidentified_not_empty=true scope=qemu-fixture-only")
	fmt.Println("PHANTOWD_VOLUME_SET_READY cloned_uuid=true aliases_deduplicated=true generation_bound=true stale_generation_refused=true unobserved_not_absent=true shuffled_complete_set=true trusted_complete_discovery=true mount_swap_rechecked=true sysfs_rechecked=true observed_opener=true readonly_sources=true all_or_error=true symlink_refused=true scope=qemu-fixture-only")
	if err := probeQEMUCollisions(dataSource.File); err != nil {
		return err
	}
	if err := unmounted(); err != nil {
		return err
	}
	return nil
}

// probeQEMUSparseGPT exercises the ARMv5 helper at a real >2 GiB pread offset
// without allocating or writing bulk fixture data. This is a regular image,
// never a block device, and it is opened read-only before probing.
func probeQEMUSparseGPT() error {
	const sectorSize = 512
	const entryArraySectors = 32
	const sectorCount = uint64(8_388_608) // 4 GiB at 512 bytes per sector
	backupHeaderLBA := sectorCount - 1
	backupEntriesLBA := backupHeaderLBA - entryArraySectors
	lastUsableLBA := backupEntriesLBA - 1

	image, err := os.CreateTemp("/run", "phantowd-probe-gpt-")
	if err != nil {
		return err
	}
	path := image.Name()
	defer os.Remove(path)
	if err := image.Truncate(int64(sectorCount * sectorSize)); err != nil {
		image.Close()
		return err
	}

	protectiveMBR := make([]byte, sectorSize)
	protectiveMBR[450] = 0xee
	binary.LittleEndian.PutUint32(protectiveMBR[454:458], 1)
	binary.LittleEndian.PutUint32(protectiveMBR[458:462], uint32(sectorCount-1))
	protectiveMBR[510], protectiveMBR[511] = 0x55, 0xaa
	if _, err := image.WriteAt(protectiveMBR, 0); err != nil {
		image.Close()
		return err
	}

	entries := make([]byte, 128*128)
	copy(entries[0:16], []byte{0x28, 0x73, 0x2a, 0xc1, 0xf8, 0x1f, 0xd2, 0x11, 0xba, 0x4b, 0x00, 0xa0, 0xc9, 0x3e, 0xc9, 0x3b})
	copy(entries[16:32], []byte{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff})
	binary.LittleEndian.PutUint64(entries[32:40], 34)
	binary.LittleEndian.PutUint64(entries[40:48], 49)
	entriesCRC := crc32.ChecksumIEEE(entries)
	if _, err := image.WriteAt(entries, 2*sectorSize); err != nil {
		image.Close()
		return err
	}
	if _, err := image.WriteAt(entries, int64(backupEntriesLBA*sectorSize)); err != nil {
		image.Close()
		return err
	}

	writeHeader := func(currentLBA, alternateLBA, entriesLBA uint64) []byte {
		header := make([]byte, sectorSize)
		copy(header[0:8], []byte("EFI PART"))
		binary.LittleEndian.PutUint32(header[8:12], 0x00010000)
		binary.LittleEndian.PutUint32(header[12:16], 92)
		binary.LittleEndian.PutUint64(header[24:32], currentLBA)
		binary.LittleEndian.PutUint64(header[32:40], alternateLBA)
		binary.LittleEndian.PutUint64(header[40:48], 34)
		binary.LittleEndian.PutUint64(header[48:56], lastUsableLBA)
		copy(header[56:72], []byte{0x98, 0xba, 0xdc, 0xfe, 0x54, 0x76, 0x10, 0x32, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10})
		binary.LittleEndian.PutUint64(header[72:80], entriesLBA)
		binary.LittleEndian.PutUint32(header[80:84], 128)
		binary.LittleEndian.PutUint32(header[84:88], 128)
		binary.LittleEndian.PutUint32(header[88:92], entriesCRC)
		binary.LittleEndian.PutUint32(header[16:20], crc32.ChecksumIEEE(header[:92]))
		return header
	}
	if _, err := image.WriteAt(writeHeader(1, backupHeaderLBA, 2), sectorSize); err != nil {
		image.Close()
		return err
	}
	if _, err := image.WriteAt(writeHeader(backupHeaderLBA, 1, backupEntriesLBA), int64(backupHeaderLBA*sectorSize)); err != nil {
		image.Close()
		return err
	}
	if err := image.Close(); err != nil {
		return err
	}

	readOnly, err := os.Open(path)
	if err != nil {
		return err
	}
	result, probeErr := runProbeFixture(readOnly)
	closeErr := readOnly.Close()
	if probeErr != nil || closeErr != nil || result.Status != "other-signature" ||
		result.SourceKind != "regular-image" || result.PartitionTable == nil ||
		result.PartitionTable.Scheme != "gpt" ||
		result.PartitionTable.ID != "fedcba98-7654-3210-fedc-ba9876543210" ||
		len(result.PartitionTable.Partitions) != 1 ||
		result.PartitionTable.Partitions[0].Start512B != 34 ||
		result.PartitionTable.Partitions[0].Size512B != 16 {
		return fmt.Errorf("sparse GPT backup-header probe failed: %v", probeErr)
	}
	fmt.Println("PHANTOWD_PARTITION_TABLE_READY gpt=true backup_header_offset_gt_2g=true sparse_regular_image=true read_only=true scope=qemu-fixture-only")
	return nil
}

func sameQEMUStorageInventory(a, b storageSnapshot) bool {
	return sameStorageSnapshot(a, b)
}
