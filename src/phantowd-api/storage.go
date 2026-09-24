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

// collectStorage reads only fixed sysfs attributes under class/block. It does
// not open /dev nodes, read disk contents, inspect filesystems, or mutate state.
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
	for _, entry := range entries {
		name := entry.Name()
		if !validBlockName(name) || seen[name] {
			return snapshot, errors.New("invalid or duplicate sysfs block name")
		}
		seen[name] = true
		base := "class/block/" + name + "/"
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

		observation := blockObservation{
			Name: name, Kind: "block", Major: major, Minor: minor,
			SizeBytes: sizeBytes, ReadOnly: readOnly, Removable: removable,
		}
		partitionText, err := readSysfsAttribute(sysfs, base+"partition")
		if err == nil {
			partitionNumber, parseErr := strconv.ParseUint(strings.TrimSpace(partitionText), 10, 32)
			if parseErr != nil || partitionNumber == 0 {
				return snapshot, errors.New("invalid sysfs partition number")
			}
			observation.Kind = "partition"
			observation.PartitionNumber = uint32(partitionNumber)
		} else if !errors.Is(err, fs.ErrNotExist) {
			return snapshot, errors.New("cannot read sysfs partition number")
		}
		if observation.Kind == "block" {
			observation.SerialStatus = observeSCSISerial(sysfs, base+"device/vpd_pg80")
			observation.WWNStatus = observeSCSIWWN(sysfs, base+"device/vpd_pg83")
		}
		snapshot.Observations = append(snapshot.Observations, observation)
	}
	snapshot.DeviceCount = len(snapshot.Observations)
	return snapshot, nil
}

func observeSCSISerial(source fs.FS, path string) identityStatus {
	page, status := readSCSVPDPage(source, path, 0x80)
	if status != identityPresent {
		return status
	}
	return parseSerialVPDPage(page)
}

func observeSCSIWWN(source fs.FS, path string) identityStatus {
	page, status := readSCSVPDPage(source, path, 0x83)
	if status != identityPresent {
		return status
	}
	_, status = parseNAAWWNPage(page)
	return status
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
	payload, ok := vpdPayload(page, 0x80)
	if !ok || len(payload) == 0 {
		return identityInvalid
	}
	for _, value := range payload {
		if value < 0x20 || value > 0x7e {
			return identityInvalid
		}
	}
	if strings.TrimSpace(string(payload)) == "" {
		return identityInvalid
	}
	return identityPresent
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
