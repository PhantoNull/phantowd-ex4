// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"sort"
	"strconv"
	"strings"
)

const (
	maxBlockEntries        = 32
	maxSysfsAttributeBytes = 128
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
	Name            string         `json:"name"`
	Kind            string         `json:"kind"`
	Major           uint32         `json:"major"`
	Minor           uint32         `json:"minor"`
	SizeBytes       uint64         `json:"size_bytes"`
	ReadOnly        bool           `json:"read_only"`
	Removable       bool           `json:"removable"`
	PartitionNumber uint32         `json:"partition_number,omitempty"`
	SerialStatus    identityStatus `json:"serial_status,omitempty"`
	WWNStatus       identityStatus `json:"wwn_status,omitempty"`
	diskSequence    uint64         `json:"-"`
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
}

// collectStorage reads only fixed sysfs attributes under class/block. It
// rejects inventory-name or whole-disk generation changes detected during the
// read, but does not create an atomic hotplug snapshot or pin device handles.
// It does not open /dev nodes, read disk contents, inspect filesystems, or
// mutate state.
func collectStorage(sysfs fs.FS) (storageSnapshot, error) {
	snapshot := storageSnapshot{
		SchemaVersion:           1,
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
			"PARTUUID, filesystem UUID, RAID membership, health and bay mapping are not collected",
			"no block device is opened and no disk content is read, assembled, mounted or modified",
			"this development endpoint is not a WD-layout support decision or migration authorization",
		},
	}
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
	for _, entry := range entries {
		name := entry.Name()
		if !validBlockName(name) || seen[name] {
			return snapshot, errors.New("invalid or duplicate sysfs block name")
		}
		seen[name] = true
		base := "class/block/" + name + "/"
		partitionText, partitionErr := readSysfsAttribute(sysfs, base+"partition")
		observation := blockObservation{Name: name, Kind: "block"}
		if partitionErr == nil {
			partitionNumber, parseErr := strconv.ParseUint(strings.TrimSpace(partitionText), 10, 32)
			if parseErr != nil || partitionNumber == 0 {
				return snapshot, errors.New("invalid sysfs partition number")
			}
			observation.Kind = "partition"
			observation.PartitionNumber = uint32(partitionNumber)
		} else if !errors.Is(partitionErr, fs.ErrNotExist) {
			return snapshot, errors.New("cannot read sysfs partition number")
		}
		if observation.Kind == "block" {
			sequence, err := readBlockDiskSequence(sysfs, base+"diskseq")
			if err != nil || diskSequences[sequence] {
				return snapshot, errors.New("invalid or duplicate sysfs block generation")
			}
			observation.diskSequence = sequence
			diskSequences[sequence] = true
		}
		deviceNumber, err := readSysfsAttribute(sysfs, base+"dev")
		if err != nil {
			return snapshot, errors.New("invalid sysfs device number")
		}
		major, minor, err := parseDeviceNumber(deviceNumber)
		if err != nil {
			return snapshot, errors.New("invalid sysfs device number")
		}
		sectorText, err := readSysfsAttribute(sysfs, base+"size")
		if err != nil {
			return snapshot, errors.New("invalid sysfs block size")
		}
		sizeBytes, err := parseSectorBytes(sectorText)
		if err != nil {
			return snapshot, errors.New("invalid sysfs block size")
		}
		readOnly, err := readSysfsFlag(sysfs, base+"ro")
		if err != nil {
			return snapshot, errors.New("invalid sysfs read-only flag")
		}
		removable, err := readSysfsFlag(sysfs, base+"removable")
		if err != nil {
			return snapshot, errors.New("invalid sysfs removable flag")
		}

		observation.Major, observation.Minor = major, minor
		observation.SizeBytes = sizeBytes
		observation.ReadOnly, observation.Removable = readOnly, removable
		if observation.Kind == "block" {
			serial, status := observeSCSISerial(sysfs, base+"device/vpd_pg80")
			observation.SerialStatus = status
			if status == identityPresent {
				serialObservations[serial] = append(serialObservations[serial], len(snapshot.Observations))
			}
			wwn, status := observeSCSIWWN(sysfs, base+"device/vpd_pg83")
			observation.WWNStatus = status
			if status == identityPresent {
				wwnObservations[wwn] = append(wwnObservations[wwn], len(snapshot.Observations))
			}
			sequence, err := readBlockDiskSequence(sysfs, base+"diskseq")
			if err != nil || sequence != observation.diskSequence {
				return snapshot, errors.New("sysfs block generation changed during observation")
			}
		}
		snapshot.Observations = append(snapshot.Observations, observation)
	}
	finalEntries, err := fs.ReadDir(sysfs, "class/block")
	if err != nil || !sameBlockInventory(entries, finalEntries) {
		return snapshot, errors.New("sysfs block inventory changed during observation")
	}
	for _, observation := range snapshot.Observations {
		if observation.Kind != "block" {
			continue
		}
		sequence, err := readBlockDiskSequence(sysfs, "class/block/"+observation.Name+"/diskseq")
		if err != nil || sequence != observation.diskSequence {
			return snapshot, errors.New("sysfs block generation changed before inventory completion")
		}
	}
	markDuplicateIdentities(snapshot.Observations, serialObservations, func(observation *blockObservation) *identityStatus {
		return &observation.SerialStatus
	})
	markDuplicateIdentities(snapshot.Observations, wwnObservations, func(observation *blockObservation) *identityStatus {
		return &observation.WWNStatus
	})
	snapshot.DeviceCount = len(snapshot.Observations)
	return snapshot, nil
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
