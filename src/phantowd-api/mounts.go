// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	maxMountEntries    = 128
	maxMountLineBytes  = 8192
	maxMountPathBytes  = 4096
	maxFilesystemBytes = 64
)

type mountSnapshot struct {
	SchemaVersion            int                `json:"schema_version"`
	ObservedAt               time.Time          `json:"observed_at"`
	Scope                    string             `json:"scope"`
	ReadOnly                 bool               `json:"read_only"`
	FilesystemContentsRead   bool               `json:"filesystem_contents_read"`
	MountOperationsPerformed bool               `json:"mount_operations_performed"`
	MountCount               int                `json:"mount_count"`
	Mounts                   []mountObservation `json:"mounts"`
	Limitations              []string           `json:"limitations"`
}

type mountObservation struct {
	MountPoint  string `json:"mount_point"`
	Filesystem  string `json:"filesystem"`
	DeviceMajor uint32 `json:"device_major"`
	DeviceMinor uint32 `json:"device_minor"`
	ReadOnly    bool   `json:"read_only"`
}

// collectMountInventory reads only the kernel-generated mount table for this
// process. It does not access mount sources, block nodes, or filesystem data.
func collectMountInventory(proc fs.FS, now time.Time) (mountSnapshot, error) {
	snapshot := mountSnapshot{
		SchemaVersion:            1,
		ObservedAt:               now.UTC(),
		Scope:                    "current-process-mount-namespace",
		ReadOnly:                 true,
		FilesystemContentsRead:   false,
		MountOperationsPerformed: false,
		Mounts:                   []mountObservation{},
		Limitations: []string{
			"this is only a snapshot of mounts already visible in this process mount namespace; unmounted disks are not probed",
			"mount source strings, root paths and raw mount options are intentionally omitted",
			"mount presence and read-only flags do not establish filesystem integrity, stable disk identity, bay mapping or WD migration compatibility",
			"no mount or unmount is performed and no block device or filesystem contents are read",
		},
	}
	data, err := readBounded(proc, "self/mountinfo")
	if err != nil {
		return snapshot, errors.New("cannot read process mount information")
	}
	observations, err := parseMountInfo(string(data))
	if err != nil {
		return snapshot, errors.New("invalid or excessive process mount information")
	}
	snapshot.Mounts = observations
	snapshot.MountCount = len(observations)
	return snapshot, nil
}

func parseMountInfo(data string) ([]mountObservation, error) {
	if len(data) > maxProcBytes {
		return nil, errors.New("mount information exceeds size limit")
	}
	lines := strings.Split(strings.TrimSuffix(data, "\n"), "\n")
	if len(lines) == 1 && strings.TrimSpace(lines[0]) == "" {
		return nil, errors.New("empty mount information")
	}
	if len(lines) > maxMountEntries {
		return nil, fmt.Errorf("mount count exceeds %d", maxMountEntries)
	}
	observations := make([]mountObservation, 0, len(lines))
	seenMountIDs := make(map[uint32]struct{}, len(lines))
	for _, line := range lines {
		if len(line) == 0 || len(line) > maxMountLineBytes {
			return nil, errors.New("empty or oversized mount information line")
		}
		fields := strings.Fields(line)
		observation, mountID, err := parseMountInfoLine(fields)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenMountIDs[mountID]; duplicate {
			return nil, errors.New("duplicate mount ID")
		}
		seenMountIDs[mountID] = struct{}{}
		observations = append(observations, observation)
	}
	sort.Slice(observations, func(i, j int) bool {
		if observations[i].MountPoint != observations[j].MountPoint {
			return observations[i].MountPoint < observations[j].MountPoint
		}
		if observations[i].DeviceMajor != observations[j].DeviceMajor {
			return observations[i].DeviceMajor < observations[j].DeviceMajor
		}
		if observations[i].DeviceMinor != observations[j].DeviceMinor {
			return observations[i].DeviceMinor < observations[j].DeviceMinor
		}
		return observations[i].Filesystem < observations[j].Filesystem
	})
	return observations, nil
}

func parseMountInfoLine(fields []string) (mountObservation, uint32, error) {
	separator := -1
	for i, field := range fields {
		if field == "-" {
			separator = i
			break
		}
	}
	if separator < 6 || len(fields)-separator < 4 {
		return mountObservation{}, 0, errors.New("invalid mount information fields")
	}
	mountID64, err := strconv.ParseUint(fields[0], 10, 32)
	if err != nil || mountID64 == 0 {
		return mountObservation{}, 0, errors.New("invalid mount ID")
	}
	if _, err := strconv.ParseUint(fields[1], 10, 32); err != nil {
		return mountObservation{}, 0, errors.New("invalid parent mount ID")
	}
	major, minor, err := parseDeviceNumber(fields[2])
	if err != nil {
		return mountObservation{}, 0, errors.New("invalid mount device number")
	}
	root, err := decodeMountField(fields[3])
	if err != nil || len(root) == 0 || root[0] != '/' {
		return mountObservation{}, 0, errors.New("invalid filesystem root")
	}
	mountPoint, err := decodeMountField(fields[4])
	if err != nil || mountPoint == "" || mountPoint[0] != '/' {
		return mountObservation{}, 0, errors.New("invalid mount point")
	}
	filesystem := fields[separator+1]
	if !validMountFilesystem(filesystem) {
		return mountObservation{}, 0, errors.New("invalid filesystem type")
	}
	readOnly, err := parseMountReadOnly(fields[5])
	if err != nil {
		return mountObservation{}, 0, err
	}
	return mountObservation{
		MountPoint: mountPoint, Filesystem: filesystem,
		DeviceMajor: major, DeviceMinor: minor, ReadOnly: readOnly,
	}, uint32(mountID64), nil
}

func parseMountReadOnly(options string) (bool, error) {
	readOnly, readWrite := false, false
	for _, option := range strings.Split(options, ",") {
		switch option {
		case "ro":
			readOnly = true
		case "rw":
			readWrite = true
		}
	}
	if readOnly == readWrite {
		return false, errors.New("mount options do not identify exactly one access mode")
	}
	return readOnly, nil
}

func decodeMountField(value string) (string, error) {
	if len(value) == 0 || len(value) > maxMountPathBytes {
		return "", errors.New("mount field exceeds size limit")
	}
	var decoded strings.Builder
	decoded.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' {
			if value[i] == 0 {
				return "", errors.New("NUL in mount field")
			}
			decoded.WriteByte(value[i])
			continue
		}
		if i+3 >= len(value) {
			return "", errors.New("incomplete mount escape")
		}
		for _, digit := range value[i+1 : i+4] {
			if digit < '0' || digit > '7' {
				return "", errors.New("invalid mount escape")
			}
		}
		parsed, err := strconv.ParseUint(value[i+1:i+4], 8, 8)
		if err != nil || parsed == 0 {
			return "", errors.New("invalid mount escape value")
		}
		decoded.WriteByte(byte(parsed))
		i += 3
	}
	return decoded.String(), nil
}

func validMountFilesystem(value string) bool {
	if value == "" || len(value) > maxFilesystemBytes {
		return false
	}
	for _, character := range value {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || strings.ContainsRune("._+-", character)) {
			return false
		}
	}
	return true
}
