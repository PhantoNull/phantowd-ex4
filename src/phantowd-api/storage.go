// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"path"
	"sort"
	"strconv"
	"strings"
)

const (
	maxBlockEntries        = 32
	maxSysfsAttributeBytes = 128
	maxSysfsBlockLinkBytes = 4096
	maxVPDPageBytes        = 4096
	linuxSysfsSectorBytes  = 512
)

type identityStatus string

const (
	identityUnavailable identityStatus = "unavailable"
	identityPresent     identityStatus = "present"
	identityInvalid     identityStatus = "invalid"
	identityAmbiguous   identityStatus = "ambiguous"
	identityUnreadable  identityStatus = "unreadable"
)

type blockObservation struct {
	Name            string             `json:"name"`
	Kind            string             `json:"kind"`
	Major           uint32             `json:"major"`
	Minor           uint32             `json:"minor"`
	SizeBytes       uint64             `json:"size_bytes"`
	ReadOnly        bool               `json:"read_only"`
	Removable       bool               `json:"removable"`
	PartitionNumber uint32             `json:"partition_number,omitempty"`
	ParentName      string             `json:"parent_name,omitempty"`
	ParentMajor     *uint32            `json:"parent_major,omitempty"`
	ParentMinor     *uint32            `json:"parent_minor,omitempty"`
	SerialStatus    identityStatus     `json:"serial_status,omitempty"`
	WWNStatus       identityStatus     `json:"wwn_status,omitempty"`
	serialEvidence  [32]byte           `json:"-"`
	wwnEvidence     [32]byte           `json:"-"`
	diskSequence    uint64             `json:"-"`
	parentDiskSeq   uint64             `json:"-"`
	sysfsTarget     string             `json:"-"`
	lowerBlocks     []blockTopologyRef `json:"-"`
}

type blockTopologyRef struct {
	Name         string
	Kind         string
	Major        uint32
	Minor        uint32
	DiskSequence uint64
}

type storageSnapshot struct {
	SchemaVersion           int                `json:"schema_version"`
	Scope                   string             `json:"scope"`
	InventoryReadOnly       bool               `json:"inventory_read_only"`
	BlockDevicesOpened      bool               `json:"block_devices_opened"`
	ContentRead             bool               `json:"content_read"`
	MutationsPerformed      bool               `json:"mutations_performed"`
	StableIdentityAvailable bool               `json:"stable_identity_available"`
	DeviceCount             int                `json:"device_count"`
	Observations            []blockObservation `json:"observations"`
	Limitations             []string           `json:"limitations"`
	collectionComplete      bool               `json:"-"`
}

// collectStorage reads only fixed sysfs attributes under class/block and
// rejects metadata changes observed on a second pass. This is a consistency
// check, not an atomic hotplug snapshot; it does not pin device handles. It
// does not open /dev nodes, read disk contents, inspect filesystems, or mutate
// state.
func collectStorage(sysfs fs.FS) (snapshot storageSnapshot, err error) {
	snapshot = storageSnapshot{
		SchemaVersion:           2,
		Scope:                   "kernel-sysfs-only",
		InventoryReadOnly:       true,
		BlockDevicesOpened:      false,
		ContentRead:             false,
		MutationsPerformed:      false,
		StableIdentityAvailable: false,
		Observations:            []blockObservation{},
		Limitations: []string{
			"kernel names and major/minor numbers are current observations, not stable identities",
			"raw serial and WWN values are never returned; only SCSI VPD availability and validation states are reported",
			"duplicate valid serial or NAA WWN values among enumerated " +
				"non-partition block nodes are marked ambiguous; aliases and " +
				"multipath topology are not resolved",
			"whole-disk kernel generations are checked before and after each " +
				"observation; the generation is transient and is never returned as " +
				"persistent identity",
			"partition parent name and major/minor are current sysfs topology in " +
				"schema v2, not durable identity; parent disk sequence is validated " +
				"internally but not returned",
			"block holder/slave relationships are validated internally and are " +
				"not returned as persistent identity or mount authorization",
			"block metadata is re-read before publication to reject observed " +
				"changes, but sysfs reads do not provide an atomic hotplug snapshot",
			"PARTUUID, filesystem UUID, RAID membership, health and bay mapping are not collected",
			"no block device is opened and no disk content is read, assembled, mounted or modified",
			"this development endpoint is not a WD-layout support decision or migration authorization",
		},
	}
	defer func() {
		if err != nil {
			snapshot = storageSnapshot{}
		}
	}()
	entries, err := fs.ReadDir(sysfs, "class/block")
	if err != nil {
		return snapshot, errors.New("cannot enumerate sysfs block entries")
	}
	if len(entries) > maxBlockEntries {
		return snapshot, fmt.Errorf("sysfs block-entry count exceeds %d", maxBlockEntries)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	seen := make(map[string]bool, len(entries))
	serialObservations := make(map[string][]int)
	wwnObservations := make(map[string][]int)
	diskSequences := make(map[uint64]bool, len(entries))
	firstPass := make([]storageBlockMetadata, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !validBlockName(name) || seen[name] {
			return snapshot, errors.New("invalid or duplicate sysfs block name")
		}
		seen[name] = true
		metadata, err := observeStorageBlockMetadata(sysfs, name)
		if err != nil {
			return snapshot, err
		}
		if metadata.kind == "block" {
			if diskSequences[metadata.diskSequence] {
				return snapshot, errors.New("invalid or duplicate sysfs block generation")
			}
			diskSequences[metadata.diskSequence] = true
		}
		observation := blockObservation{
			Name: name, Kind: metadata.kind, Major: metadata.major, Minor: metadata.minor,
			SizeBytes: metadata.sizeBytes, ReadOnly: metadata.readOnly,
			Removable: metadata.removable, PartitionNumber: metadata.partitionNumber,
			SerialStatus: metadata.serialStatus, WWNStatus: metadata.wwnStatus,
			serialEvidence: vpdObservationEvidence("serial", metadata.serial),
			wwnEvidence:    vpdObservationEvidence("wwn", metadata.wwn),
			diskSequence:   metadata.diskSequence,
			sysfsTarget:    metadata.sysfsTarget,
		}
		if metadata.kind == "block" {
			if metadata.serialStatus == identityPresent {
				serialObservations[metadata.serial] = append(serialObservations[metadata.serial], len(snapshot.Observations))
			}
			if metadata.wwnStatus == identityPresent {
				wwnObservations[metadata.wwn] = append(wwnObservations[metadata.wwn], len(snapshot.Observations))
			}
		}
		snapshot.Observations = append(snapshot.Observations, observation)
		firstPass = append(firstPass, metadata)
	}
	if err := correlateStoragePartitionParents(snapshot.Observations, firstPass); err != nil {
		return snapshot, errors.New("cannot establish complete partition parent topology")
	}
	if err := correlateStorageBlockRelations(snapshot.Observations, firstPass); err != nil {
		return snapshot, errors.New("cannot establish complete block holder/slave topology")
	}
	for index, observation := range snapshot.Observations {
		metadata, err := observeStorageBlockMetadata(sysfs, observation.Name)
		if err != nil || !sameStorageBlockMetadata(metadata, firstPass[index]) {
			return snapshot, errors.New("sysfs block metadata changed before inventory completion")
		}
	}
	finalEntries, err := fs.ReadDir(sysfs, "class/block")
	if err != nil || !sameBlockInventory(entries, finalEntries) {
		return snapshot, errors.New("sysfs block inventory changed during observation")
	}
	markDuplicateIdentities(snapshot.Observations, serialObservations, func(observation *blockObservation) *identityStatus {
		return &observation.SerialStatus
	})
	markDuplicateIdentities(snapshot.Observations, wwnObservations, func(observation *blockObservation) *identityStatus {
		return &observation.WWNStatus
	})
	snapshot.DeviceCount = len(snapshot.Observations)
	snapshot.collectionComplete = true
	return snapshot, nil
}

// vpdObservationEvidence is an in-process equality token for re-observation,
// not a durable device identity. The raw value stays in collection-local
// metadata and is never retained by the API snapshot or serialized.
func vpdObservationEvidence(kind, value string) [32]byte {
	if value == "" {
		return [32]byte{}
	}
	return sha256.Sum256([]byte("phantowd-vpd-observation-v1\x00" + kind + "\x00" + value))
}

type storageBlockMetadata struct {
	kind            string
	major           uint32
	minor           uint32
	sizeBytes       uint64
	readOnly        bool
	removable       bool
	partitionNumber uint32
	diskSequence    uint64
	sysfsTarget     string
	holderTargets   []string
	slaveTargets    []string
	serial          string
	serialStatus    identityStatus
	wwn             string
	wwnStatus       identityStatus
}

func observeStorageBlockMetadata(sysfs fs.FS, name string) (storageBlockMetadata, error) {
	base := "class/block/" + name + "/"
	metadata := storageBlockMetadata{kind: "block"}
	target, err := readSysfsBlockTarget(sysfs, name)
	if err != nil {
		return metadata, errors.New("invalid sysfs block link")
	}
	metadata.sysfsTarget = target
	// Partitions expose holders; reciprocal slaves links belong to a whole gendisk.
	metadata.holderTargets, err = readSysfsBlockRelations(sysfs, target, "holders")
	if err != nil {
		return metadata, errors.New("cannot read sysfs block holders")
	}
	partitionText, partitionErr := readSysfsAttribute(sysfs, base+"partition")
	if partitionErr == nil {
		partitionNumber, parseErr := strconv.ParseUint(strings.TrimSpace(partitionText), 10, 32)
		if parseErr != nil || partitionNumber == 0 {
			return metadata, errors.New("invalid sysfs partition number")
		}
		metadata.kind = "partition"
		metadata.partitionNumber = uint32(partitionNumber)
	} else if !errors.Is(partitionErr, fs.ErrNotExist) {
		return metadata, errors.New("cannot read sysfs partition number")
	}
	if metadata.kind == "block" {
		// Linux exposes slaves on a whole gendisk, not on its partition nodes.
		metadata.slaveTargets, err = readSysfsBlockRelations(sysfs, target, "slaves")
		if err != nil {
			return metadata, errors.New("cannot read sysfs block slaves")
		}
		sequence, err := readBlockDiskSequence(sysfs, base+"diskseq")
		if err != nil {
			return metadata, errors.New("invalid sysfs block generation")
		}
		metadata.diskSequence = sequence
	}
	deviceNumber, err := readSysfsAttribute(sysfs, base+"dev")
	if err != nil {
		return metadata, errors.New("invalid sysfs device number")
	}
	metadata.major, metadata.minor, err = parseDeviceNumber(deviceNumber)
	if err != nil {
		return metadata, errors.New("invalid sysfs device number")
	}
	sectorText, err := readSysfsAttribute(sysfs, base+"size")
	if err != nil {
		return metadata, errors.New("invalid sysfs block size")
	}
	metadata.sizeBytes, err = parseSectorBytes(sectorText)
	if err != nil {
		return metadata, errors.New("invalid sysfs block size")
	}
	metadata.readOnly, err = readSysfsFlag(sysfs, base+"ro")
	if err != nil {
		return metadata, errors.New("invalid sysfs read-only flag")
	}
	metadata.removable, err = readSysfsFlag(sysfs, base+"removable")
	if err != nil {
		return metadata, errors.New("invalid sysfs removable flag")
	}
	if metadata.kind == "block" {
		metadata.serial, metadata.serialStatus = observeSCSISerial(sysfs, base+"device/vpd_pg80")
		metadata.wwn, metadata.wwnStatus = observeSCSIWWN(sysfs, base+"device/vpd_pg83")
		sequence, err := readBlockDiskSequence(sysfs, base+"diskseq")
		if err != nil || sequence != metadata.diskSequence {
			return metadata, errors.New("sysfs block generation changed during observation")
		}
	}
	return metadata, nil
}

func readSysfsBlockRelations(sysfs fs.FS, ownerTarget, relation string) ([]string, error) {
	if relation != "holders" && relation != "slaves" {
		return nil, errors.New("invalid sysfs block relation")
	}
	directory := ownerTarget + "/" + relation
	entries, err := fs.ReadDir(sysfs, directory)
	if err != nil || len(entries) > maxBlockEntries {
		return nil, errors.New("cannot enumerate bounded sysfs block relations")
	}
	linkFS, ok := sysfs.(fs.ReadLinkFS)
	if !ok {
		return nil, errors.New("sysfs filesystem cannot read block relations")
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	targets := make([]string, 0, len(entries))
	seenNames := make(map[string]bool, len(entries))
	seenTargets := make(map[string]bool, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !validBlockName(name) || seenNames[name] {
			return nil, errors.New("invalid or duplicate sysfs block relation name")
		}
		seenNames[name] = true
		linkPath := directory + "/" + name
		target, err := linkFS.ReadLink(linkPath)
		if err != nil || target == "" || len(target) > maxSysfsBlockLinkBytes ||
			strings.IndexByte(target, 0) >= 0 || path.IsAbs(target) {
			return nil, errors.New("invalid sysfs block relation link")
		}
		resolved := path.Clean(path.Join(directory, target))
		if !fs.ValidPath(resolved) || !strings.HasPrefix(resolved, "devices/") || path.Base(resolved) != name || seenTargets[resolved] {
			return nil, errors.New("sysfs block relation escaped or duplicated its device tree")
		}
		seenTargets[resolved] = true
		targets = append(targets, resolved)
	}
	return targets, nil
}

func correlateStorageBlockRelations(observations []blockObservation, metadata []storageBlockMetadata) error {
	if len(observations) != len(metadata) {
		return errors.New("storage relation inventory does not match observations")
	}
	byTarget := make(map[string]int, len(metadata))
	for index, item := range metadata {
		if item.sysfsTarget == "" {
			return errors.New("block relation has no validated device target")
		}
		if _, exists := byTarget[item.sysfsTarget]; exists {
			return errors.New("multiple block nodes share one sysfs target")
		}
		byTarget[item.sysfsTarget] = index
	}
	for index, item := range metadata {
		for _, holderTarget := range item.holderTargets {
			holderIndex, exists := byTarget[holderTarget]
			if !exists || !containsString(metadata[holderIndex].slaveTargets, item.sysfsTarget) {
				return errors.New("holder relation is absent, unobserved, or not reciprocal")
			}
		}
		for _, slaveTarget := range item.slaveTargets {
			slaveIndex, exists := byTarget[slaveTarget]
			if !exists || !containsString(metadata[slaveIndex].holderTargets, item.sysfsTarget) {
				return errors.New("slave relation is absent, unobserved, or not reciprocal")
			}
			lower := observations[slaveIndex]
			observations[index].lowerBlocks = append(observations[index].lowerBlocks, blockTopologyRef{
				Name: lower.Name, Kind: lower.Kind, Major: lower.Major, Minor: lower.Minor,
				DiskSequence: lower.diskSequence,
			})
		}
	}
	return nil
}

func sameStorageBlockMetadata(a, b storageBlockMetadata) bool {
	return a.kind == b.kind && a.major == b.major && a.minor == b.minor &&
		a.sizeBytes == b.sizeBytes && a.readOnly == b.readOnly && a.removable == b.removable &&
		a.partitionNumber == b.partitionNumber && a.diskSequence == b.diskSequence &&
		a.sysfsTarget == b.sysfsTarget && a.serial == b.serial && a.serialStatus == b.serialStatus &&
		a.wwn == b.wwn && a.wwnStatus == b.wwnStatus &&
		sameStringList(a.holderTargets, b.holderTargets) && sameStringList(a.slaveTargets, b.slaveTargets)
}

func sameStringList(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func sameBlockObservation(a, b blockObservation) bool {
	if a.Name != b.Name || a.Kind != b.Kind || a.Major != b.Major || a.Minor != b.Minor ||
		a.SizeBytes != b.SizeBytes || a.ReadOnly != b.ReadOnly || a.Removable != b.Removable ||
		a.PartitionNumber != b.PartitionNumber || a.SerialStatus != b.SerialStatus ||
		a.WWNStatus != b.WWNStatus || a.serialEvidence != b.serialEvidence || a.wwnEvidence != b.wwnEvidence ||
		a.diskSequence != b.diskSequence || a.sysfsTarget != b.sysfsTarget ||
		a.ParentName != b.ParentName || !sameOptionalUint32(a.ParentMajor, b.ParentMajor) ||
		!sameOptionalUint32(a.ParentMinor, b.ParentMinor) || a.parentDiskSeq != b.parentDiskSeq ||
		len(a.lowerBlocks) != len(b.lowerBlocks) {
		return false
	}
	for index := range a.lowerBlocks {
		if a.lowerBlocks[index] != b.lowerBlocks[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func readSysfsBlockTarget(sysfs fs.FS, name string) (string, error) {
	linkFS, ok := sysfs.(fs.ReadLinkFS)
	if !ok {
		return "", errors.New("sysfs filesystem cannot read block links")
	}
	target, err := linkFS.ReadLink("class/block/" + name)
	if err != nil || target == "" || len(target) > maxSysfsBlockLinkBytes ||
		strings.IndexByte(target, 0) >= 0 || path.IsAbs(target) {
		return "", errors.New("invalid sysfs block link target")
	}
	resolved := path.Clean(path.Join("class/block", target))
	if !fs.ValidPath(resolved) || !strings.HasPrefix(resolved, "devices/") || path.Base(resolved) != name {
		return "", errors.New("sysfs block link escaped the device tree")
	}
	return resolved, nil
}

func correlateStoragePartitionParents(observations []blockObservation, metadata []storageBlockMetadata) error {
	if len(observations) != len(metadata) {
		return errors.New("storage topology does not match its observations")
	}
	wholeDisksByTarget := make(map[string][]int, len(metadata))
	for index, item := range metadata {
		if item.kind == "block" {
			wholeDisksByTarget[item.sysfsTarget] = append(wholeDisksByTarget[item.sysfsTarget], index)
		}
	}
	for index, item := range metadata {
		if item.kind != "partition" {
			continue
		}
		parents := wholeDisksByTarget[path.Dir(item.sysfsTarget)]
		if len(parents) != 1 {
			return errors.New("partition does not resolve to one whole-disk node")
		}
		parentIndex := parents[0]
		parent := metadata[parentIndex]
		parentMajor := parent.major
		parentMinor := parent.minor
		observations[index].ParentName = observations[parentIndex].Name
		observations[index].ParentMajor = &parentMajor
		observations[index].ParentMinor = &parentMinor
		observations[index].parentDiskSeq = parent.diskSequence
	}
	return nil
}

func sameOptionalUint32(a, b *uint32) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func sameBlockInventory(before, after []fs.DirEntry) bool {
	if len(before) != len(after) {
		return false
	}
	sort.Slice(after, func(i, j int) bool { return after[i].Name() < after[j].Name() })
	for index := range before {
		if before[index].Name() != after[index].Name() {
			return false
		}
	}
	return true
}

func readBlockDiskSequence(source fs.FS, path string) (uint64, error) {
	value, err := readSysfsAttribute(source, path)
	if err != nil {
		return 0, err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("invalid sysfs disk sequence")
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, errors.New("invalid sysfs disk sequence")
		}
	}
	sequence, err := strconv.ParseUint(value, 10, 64)
	if err != nil || sequence == 0 {
		return 0, errors.New("invalid sysfs disk sequence")
	}
	return sequence, nil
}

func markDuplicateIdentities(observations []blockObservation, matches map[string][]int, statusField func(*blockObservation) *identityStatus) {
	for _, indices := range matches {
		if len(indices) < 2 {
			continue
		}
		for _, index := range indices {
			if index >= 0 && index < len(observations) {
				*statusField(&observations[index]) = identityAmbiguous
			}
		}
	}
}

func observeSCSISerial(source fs.FS, path string) (string, identityStatus) {
	page, status := readSCSVPDPage(source, path, 0x80)
	if status != identityPresent {
		return "", status
	}
	return parseSerialVPDValue(page)
}

func observeSCSIWWN(source fs.FS, path string) (string, identityStatus) {
	page, status := readSCSVPDPage(source, path, 0x83)
	if status != identityPresent {
		return "", status
	}
	return parseNAAWWNPage(page)
}

func readSCSVPDPage(source fs.FS, path string, pageCode byte) ([]byte, identityStatus) {
	file, err := source.Open(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, identityUnavailable
	}
	if err != nil {
		return nil, identityUnreadable
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxVPDPageBytes+1))
	if err != nil {
		return nil, identityUnreadable
	}
	if len(data) > maxVPDPageBytes {
		return nil, identityInvalid
	}
	if _, ok := vpdPayload(data, pageCode); !ok {
		return nil, identityInvalid
	}
	return data, identityPresent
}

func parseSerialVPDPage(page []byte) identityStatus {
	_, status := parseSerialVPDValue(page)
	return status
}

func parseSerialVPDValue(page []byte) (string, identityStatus) {
	payload, ok := vpdPayload(page, 0x80)
	if !ok || len(payload) == 0 {
		return "", identityInvalid
	}
	for _, value := range payload {
		if value < 0x20 || value > 0x7e {
			return "", identityInvalid
		}
	}
	value := strings.TrimSpace(string(payload))
	if value == "" {
		return "", identityInvalid
	}
	return value, identityPresent
}

// parseNAAWWNPage returns a canonical value only to its caller. Public API
// responses expose the status but never the serial or WWN value itself.
func parseNAAWWNPage(page []byte) (string, identityStatus) {
	payload, ok := vpdPayload(page, 0x83)
	if !ok {
		return "", identityInvalid
	}
	identifiers := make(map[string]struct{})
	for offset := 0; offset < len(payload); {
		if len(payload)-offset < 4 {
			return "", identityInvalid
		}
		descriptor := payload[offset : offset+4]
		length := int(descriptor[3])
		if length == 0 || length > len(payload)-offset-4 {
			return "", identityInvalid
		}
		codeSet := descriptor[0] & 0x0f
		association := (descriptor[1] >> 4) & 0x03
		designatorType := descriptor[1] & 0x0f
		value := payload[offset+4 : offset+4+length]
		if codeSet == 0x01 && association == 0 && designatorType == 0x03 {
			naa := value[0] >> 4
			validWidth := (naa == 0x02 || naa == 0x03 || naa == 0x05) && length == 8 || naa == 0x06 && length == 16
			if !validWidth || allZero(value) {
				return "", identityInvalid
			}
			identifiers[hex.EncodeToString(value)] = struct{}{}
		}
		offset += 4 + length
	}
	if len(identifiers) == 0 {
		return "", identityUnavailable
	}
	if len(identifiers) > 1 {
		return "", identityAmbiguous
	}
	for value := range identifiers {
		return "naa." + value, identityPresent
	}
	return "", identityUnavailable
}

func vpdPayload(page []byte, expectedCode byte) ([]byte, bool) {
	if len(page) < 4 || len(page) > maxVPDPageBytes || page[1] != expectedCode {
		return nil, false
	}
	length := int(page[2])<<8 | int(page[3])
	if length != len(page)-4 {
		return nil, false
	}
	return page[4:], true
}

func allZero(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}

func readSysfsAttribute(source fs.FS, path string) (string, error) {
	file, err := source.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, maxSysfsAttributeBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > maxSysfsAttributeBytes {
		return "", errors.New("sysfs attribute exceeds size limit")
	}
	return string(data), nil
}

func readSysfsFlag(source fs.FS, path string) (bool, error) {
	value, err := readSysfsAttribute(source, path)
	if err != nil {
		return false, err
	}
	switch strings.TrimSpace(value) {
	case "0":
		return false, nil
	case "1":
		return true, nil
	default:
		return false, errors.New("invalid sysfs boolean")
	}
}

func parseDeviceNumber(value string) (uint32, uint32, error) {
	fields := strings.Split(strings.TrimSpace(value), ":")
	if len(fields) != 2 {
		return 0, 0, errors.New("invalid major:minor value")
	}
	major, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	minor, err := strconv.ParseUint(fields[1], 10, 32)
	if err != nil {
		return 0, 0, err
	}
	return uint32(major), uint32(minor), nil
}

func parseSectorBytes(value string) (uint64, error) {
	sectors, err := strconv.ParseUint(strings.TrimSpace(value), 10, 64)
	if err != nil {
		return 0, err
	}
	if sectors > math.MaxUint64/linuxSysfsSectorBytes {
		return 0, errors.New("sysfs sector count overflows byte capacity")
	}
	return sectors * linuxSysfsSectorBytes, nil
}

func validBlockName(name string) bool {
	if name == "" || name == "." || name == ".." || len(name) > 64 {
		return false
	}
	for _, character := range name {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._-", character)) {
			return false
		}
	}
	return true
}
