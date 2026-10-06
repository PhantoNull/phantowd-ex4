// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package storageinventory validates the project-owned, synthetic v1 storage
// inventory. It does not probe, mount, or modify storage devices.
package storageinventory

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	format        = "phantowd-storage-inventory"
	schemaVersion = 1
	maxInputBytes = 1 << 20
)

// Manifest is a project-owned host inventory format. Its field names and
// relationships are not claimed to describe any WD XML or on-disk format.
type Manifest struct {
	Format        string      `json:"format"`
	SchemaVersion int         `json:"schema_version"`
	Disks         []Disk      `json:"disks"`
	Partitions    []Partition `json:"partitions"`
	Volumes       []Volume    `json:"volumes"`
}

// Disk combines stable identifiers with current, explicitly non-authoritative
// bay and kernel-device observations.
type Disk struct {
	ID     string `json:"id"`
	WWN    string `json:"wwn"`
	Serial string `json:"serial"`
	Bay    int    `json:"bay"`
	Device string `json:"device"`
}

// Partition is linked to its parent disk by an inventory-local ID.
type Partition struct {
	ID       string `json:"id"`
	DiskID   string `json:"disk_id"`
	Number   int    `json:"number"`
	PARTUUID string `json:"partuuid"`
}

// Volume records a logical volume number plus stable filesystem and optional
// md-array identities. Member references point to inventory-local partitions.
type Volume struct {
	ID                  string   `json:"id"`
	LogicalVolumeNumber int      `json:"logical_volume_number"`
	FilesystemUUID      string   `json:"filesystem_uuid"`
	FilesystemType      string   `json:"filesystem_type"`
	MDUUID              string   `json:"md_uuid,omitempty"`
	MemberPartitionIDs  []string `json:"member_partition_ids"`
}

// VolumeSummary deliberately excludes source identifiers and current topology.
type VolumeSummary struct {
	LogicalVolumeNumber int    `json:"logical_volume_number"`
	HistoricalDataMount string `json:"historical_data_mount"`
	IdentityBasis       string `json:"identity_basis"`
	IdentityFingerprint string `json:"identity_fingerprint"`
}

// Report contains only fixed diagnostics, counts and redacted derived identity.
type Report struct {
	Format                   string          `json:"format"`
	SchemaVersion            int             `json:"schema_version"`
	Valid                    bool            `json:"valid"`
	IdentityMaterialRedacted bool            `json:"identity_material_redacted"`
	DiskCount                int             `json:"disk_count"`
	PartitionCount           int             `json:"partition_count"`
	VolumeCount              int             `json:"volume_count"`
	Volumes                  []VolumeSummary `json:"volumes"`
	Violations               []string        `json:"violations"`
	Limitations              []string        `json:"limitations"`
}

// Inspect reads one bounded JSON object, validates its schema and references,
// and emits a redacted report. Invalid-but-parseable inventories return a
// report with Valid=false; malformed or unsupported JSON returns an error.
func Inspect(input io.Reader) (Report, error) {
	report := Report{
		Format:                   format,
		SchemaVersion:            schemaVersion,
		IdentityMaterialRedacted: true,
		Volumes:                  []VolumeSummary{},
		Violations:               []string{},
		Limitations: []string{
			"this is a project-owned synthetic schema, not a parser or description of WD XML",

			"bay, kernel-device names and inventory-local IDs are observations or references, never volume identity",
			"the historical HD_* path is a compatibility hint derived from the logical number, not an identity or mount instruction",
			"fingerprints are deterministic summaries of supplied identifiers, not proof of authenticity, health, or supported layout",
			"this command reads only the supplied JSON file and never probes, assembles, mounts, or modifies storage",
		},
	}

	data, err := io.ReadAll(io.LimitReader(input, maxInputBytes+1))
	if err != nil {
		return report, err
	}
	if len(data) > maxInputBytes {
		return report, fmt.Errorf("inventory exceeds %d-byte limit", maxInputBytes)
	}
	if !utf8.Valid(data) {
		return report, errors.New("inventory is not valid UTF-8")
	}
	if err := rejectDuplicateJSONKeys(data); err != nil {
		return report, err
	}
	if err := checkExactJSONKeys(data); err != nil {
		return report, err
	}

	var manifest Manifest
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return report, fmt.Errorf("invalid storage inventory JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return report, err
	}

	report.DiskCount = len(manifest.Disks)
	report.PartitionCount = len(manifest.Partitions)
	report.VolumeCount = len(manifest.Volumes)
	report.Violations = validate(manifest)
	if len(report.Violations) != 0 {
		return report, nil
	}

	report.Valid = true
	for _, volume := range manifest.Volumes {
		basis := "filesystem"
		identity := "phantowd-storage-volume-v1\nfilesystem:" + canonical(volume.FilesystemUUID)
		if volume.MDUUID != "" {
			basis = "filesystem+md-array"
			identity += "\nmd-array:" + canonical(volume.MDUUID)
		}
		digest := sha256.Sum256([]byte(identity))
		report.Volumes = append(report.Volumes, VolumeSummary{
			LogicalVolumeNumber: volume.LogicalVolumeNumber,
			HistoricalDataMount: historicalDataMount(volume.LogicalVolumeNumber),
			IdentityBasis:       basis,
			IdentityFingerprint: hex.EncodeToString(digest[:]),
		})
	}
	sort.Slice(report.Volumes, func(i, j int) bool {
		return report.Volumes[i].LogicalVolumeNumber < report.Volumes[j].LogicalVolumeNumber
	})
	return report, nil
}

func validate(manifest Manifest) []string {
	var violations []string
	add := func(message string) { violations = append(violations, message) }
	if manifest.Format != format {
		add("unsupported inventory format")
	}
	if manifest.SchemaVersion != schemaVersion {
		add("unsupported inventory schema version")
	}
	if len(manifest.Disks) == 0 || len(manifest.Disks) > 4 {
		add("disk count must be between 1 and 4")
	}
	if len(manifest.Partitions) == 0 || len(manifest.Partitions) > 64 {
		add("partition count must be between 1 and 64")
	}
	if len(manifest.Volumes) == 0 || len(manifest.Volumes) > 4 {
		add("volume count must be between 1 and 4")
	}

	diskIDs := make(map[string]bool)
	bays := make(map[int]bool)
	devices := make(map[string]bool)
	wwns := make(map[string]bool)
	serials := make(map[string]bool)
	for _, disk := range manifest.Disks {
		id := canonical(disk.ID)
		device := canonical(disk.Device)
		wwn := canonical(disk.WWN)
		serial := canonical(disk.Serial)
		if !validToken(disk.ID) || diskIDs[id] {
			add("disk IDs must be present and unique")
		}
		diskIDs[id] = true
		if disk.Bay < 1 || disk.Bay > 4 || bays[disk.Bay] {
			add("disk bay observations must be unique values from 1 through 4")
		}
		bays[disk.Bay] = true
		if !validDevice(disk.Device) || devices[device] {
			add("kernel-device observations must be present and unique")
		}
		devices[device] = true
		if wwn == "" && serial == "" {
			add("each disk requires at least one stable WWN or serial identifier")
		}
		if wwn != "" && (!validToken(disk.WWN) || wwns[wwn]) {
			add("non-empty WWN identifiers must be valid and unique")
		}
		if serial != "" && (!validToken(disk.Serial) || serials[serial]) {
			add("non-empty serial identifiers must be valid and unique")
		}
		if wwn != "" {
			wwns[wwn] = true
		}
		if serial != "" {
			serials[serial] = true
		}
	}

	partitionIDs := make(map[string]bool)
	partuuids := make(map[string]bool)
	partitionSlots := make(map[string]bool)
	for _, partition := range manifest.Partitions {
		id := canonical(partition.ID)
		diskID := canonical(partition.DiskID)
		partuuid := canonical(partition.PARTUUID)
		if !validToken(partition.ID) || partitionIDs[id] {
			add("partition IDs must be present and unique")
		}
		partitionIDs[id] = true
		if !diskIDs[diskID] {
			add("partition references an unknown disk")
		}
		if partition.Number < 1 || partition.Number > 128 {
			add("partition numbers must be between 1 and 128")
		}
		slot := diskID + ":" + fmt.Sprint(partition.Number)
		if partitionSlots[slot] {
			add("partition numbers must be unique within each disk")
		}
		partitionSlots[slot] = true
		if !validToken(partition.PARTUUID) || partuuids[partuuid] {
			add("PARTUUID identifiers must be present, valid, and unique")
		}
		partuuids[partuuid] = true
	}

	volumeIDs := make(map[string]bool)
	logicalNumbers := make(map[int]bool)
	filesystemUUIDs := make(map[string]bool)
	mdUUIDs := make(map[string]bool)
	partitionOwners := make(map[string]bool)
	for _, volume := range manifest.Volumes {
		id := canonical(volume.ID)
		filesystemUUID := canonical(volume.FilesystemUUID)
		mdUUID := canonical(volume.MDUUID)
		if !validToken(volume.ID) || volumeIDs[id] {
			add("volume IDs must be present and unique")
		}
		volumeIDs[id] = true
		if volume.LogicalVolumeNumber < 1 || volume.LogicalVolumeNumber > 4 || logicalNumbers[volume.LogicalVolumeNumber] {
			add("logical volume numbers must be unique values from 1 through 4")
		}
		logicalNumbers[volume.LogicalVolumeNumber] = true
		if !validToken(volume.FilesystemUUID) || filesystemUUIDs[filesystemUUID] {
			add("filesystem UUIDs must be present, valid, and unique")
		}
		filesystemUUIDs[filesystemUUID] = true
		if !validToken(volume.FilesystemType) {
			add("filesystem types must be present valid tokens")
		}
		if volume.MDUUID != "" && (!validToken(volume.MDUUID) || mdUUIDs[mdUUID]) {
			add("non-empty md UUIDs must be valid and unique")
		}
		if mdUUID != "" {
			mdUUIDs[mdUUID] = true
		}
		if len(volume.MemberPartitionIDs) == 0 || len(volume.MemberPartitionIDs) > 16 {
			add("each volume must reference between 1 and 16 member partitions")
		}
		members := make(map[string]bool)
		for _, memberID := range volume.MemberPartitionIDs {
			member := canonical(memberID)
			if !validToken(memberID) || members[member] {
				add("volume member references must be present and unique")
			}
			members[member] = true
			if !partitionIDs[member] {
				add("volume references an unknown partition")
			}
			if partitionOwners[member] {
				add("a partition cannot be assigned to multiple volumes")
			}
			partitionOwners[member] = true
		}
	}
	return violations
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanJSONValue(decoder); err != nil {
		return fmt.Errorf("invalid storage inventory JSON: %w", err)
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("storage inventory must contain exactly one JSON value")
		}
		return fmt.Errorf("invalid storage inventory JSON: %w", err)
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, composite := token.(json.Delim)
	if !composite {
		return nil
	}
	switch delimiter {
	case '{':
		keys := make(map[string]bool)
		for decoder.More() {
			token, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := token.(string)
			if !ok {
				return errors.New("JSON object key is not a string")
			}
			if keys[key] {
				return errors.New("duplicate JSON object key")
			}
			keys[key] = true
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, '}')
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		return consumeJSONDelimiter(decoder, ']')
	default:
		return errors.New("unexpected JSON delimiter")
	}
}

func consumeJSONDelimiter(decoder *json.Decoder, expected json.Delim) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != expected {
		return errors.New("mismatched JSON delimiter")
	}
	return nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	if err := decoder.Decode(new(any)); err != io.EOF {
		if err == nil {
			return errors.New("storage inventory must contain exactly one JSON value")
		}
		return fmt.Errorf("invalid trailing JSON data: %w", err)
	}
	return nil
}

func checkExactJSONKeys(data []byte) error {
	var root map[string]json.RawMessage
	if err := json.Unmarshal(data, &root); err != nil {
		return fmt.Errorf("invalid storage inventory JSON: %w", err)
	}
	if root == nil {
		return errors.New("storage inventory must be a JSON object")
	}
	if err := checkObjectKeys(root, "storage inventory", "format", "schema_version", "disks", "partitions", "volumes"); err != nil {
		return err
	}
	if err := checkArrayObjectKeys(root["disks"], "disk", "id", "wwn", "serial", "bay", "device"); err != nil {
		return err
	}
	if err := checkArrayObjectKeys(root["partitions"], "partition", "id", "disk_id", "number", "partuuid"); err != nil {
		return err
	}
	return checkArrayObjectKeys(root["volumes"], "volume", "id", "logical_volume_number", "filesystem_uuid", "filesystem_type", "md_uuid", "member_partition_ids")
}

func checkArrayObjectKeys(data json.RawMessage, objectName string, allowed ...string) error {
	if len(data) == 0 || bytes.Equal(bytes.TrimSpace(data), []byte("null")) {
		return nil
	}
	var objects []json.RawMessage
	if err := json.Unmarshal(data, &objects); err != nil {
		return fmt.Errorf("%s collection must be a JSON array", objectName)
	}
	for _, object := range objects {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(object, &fields); err != nil || fields == nil {
			return fmt.Errorf("%s entries must be JSON objects", objectName)
		}
		if err := checkObjectKeys(fields, objectName, allowed...); err != nil {
			return err
		}
	}
	return nil
}

func checkObjectKeys(fields map[string]json.RawMessage, objectName string, allowed ...string) error {
	permitted := make(map[string]bool, len(allowed))
	for _, key := range allowed {
		permitted[key] = true
	}
	for key := range fields {
		if !permitted[key] {
			return fmt.Errorf("unsupported or case-mismatched key in %s", objectName)
		}
	}
	return nil
}

func validToken(value string) bool {
	if value == "" || len(value) > 128 || strings.TrimSpace(value) != value {
		return false
	}
	for _, r := range value {
		if !((r >= 'A' && r <= 'Z') || (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || strings.ContainsRune("._:+-", r)) {
			return false
		}
	}
	return true
}

func validDevice(value string) bool {
	return value != "" && len(value) <= 128 && strings.HasPrefix(value, "/dev/") && validToken(strings.TrimPrefix(value, "/dev/"))
}

func canonical(value string) string { return strings.ToLower(strings.TrimSpace(value)) }

func historicalDataMount(logicalNumber int) string {
	return fmt.Sprintf("/mnt/HD/HD_%c2", rune('a'+logicalNumber-1))
}
