// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

const storageBrokerProtocolVersion = 2
const storageBrokerMaxFrameBytes = 64 * 1024

var errStorageBrokerUnavailable = errors.New("storage broker unavailable")

var storageBrokerJSONKeys = map[string]bool{
	"version": true, "status": true, "snapshot": true, "gpt_observation": true,
	"eligible_candidate_count": true, "gpt_disk_count": true, "partition_count": true,
	"unsupported_or_non_gpt_count": true, "gpt_coverage": true,
	"ambiguous_disk_guid_count": true, "ambiguous_partuuid_count": true,
	"identity_evidence_incomplete": true, "mount_performed": true, "assembly_performed": true, "import_performed": true,
	"schema_version": true, "scope": true, "inventory_read_only": true,
	"block_devices_opened": true, "content_read": true, "mutations_performed": true,
	"stable_identity_available": true, "device_count": true, "observations": true,
	"limitations": true, "name": true, "kind": true, "major": true, "minor": true,
	"size_bytes": true, "read_only": true, "removable": true,
	"partition_number": true, "parent_name": true, "parent_major": true,
	"parent_minor": true, "serial_status": true, "wwn_status": true,
}

var storageBrokerRequestJSONKeys = map[string]bool{"version": true, "operation": true}

const (
	storageBrokerOperationInventory = "inventory"
	storageBrokerOperationGPT       = "observe-gpt"
)

type storageBrokerRequest struct {
	Version   int    `json:"version"`
	Operation string `json:"operation"`
}

// storageBrokerResponse is the only broker-to-API message. The API sends no
// request body, device name, path, command, or descriptor; connecting asks for
// one bounded read-only inventory response.
type storageBrokerResponse struct {
	Version        int                           `json:"version"`
	Status         string                        `json:"status"`
	Snapshot       *storageSnapshot              `json:"snapshot,omitempty"`
	GPTObservation *storageGPTObservationSummary `json:"gpt_observation,omitempty"`
}

func encodeStorageBrokerRequest(operation string) ([]byte, error) {
	if operation != storageBrokerOperationInventory && operation != storageBrokerOperationGPT {
		return nil, errStorageBrokerUnavailable
	}
	data, err := json.Marshal(storageBrokerRequest{Version: storageBrokerProtocolVersion, Operation: operation})
	if err != nil || len(data) == 0 || len(data) > storageBrokerMaxFrameBytes {
		return nil, errStorageBrokerUnavailable
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	return frame, nil
}

func decodeStorageBrokerRequest(reader io.Reader) (storageBrokerRequest, error) {
	data, err := readStorageBrokerFrame(reader)
	if err != nil {
		return storageBrokerRequest{}, err
	}
	var request storageBrokerRequest
	if configjson.Decode(bytes.NewReader(data), &request, storageBrokerMaxFrameBytes, 4, storageBrokerRequestJSONKeys) != nil ||
		request.Version != storageBrokerProtocolVersion ||
		(request.Operation != storageBrokerOperationInventory && request.Operation != storageBrokerOperationGPT) {
		return storageBrokerRequest{}, errStorageBrokerUnavailable
	}
	return request, nil
}

func encodeStorageBrokerFrame(response storageBrokerResponse) ([]byte, error) {
	if !validStorageBrokerResponse(response) {
		return nil, errStorageBrokerUnavailable
	}
	data, err := json.Marshal(response)
	if err != nil || len(data) == 0 || len(data) > storageBrokerMaxFrameBytes {
		return nil, errStorageBrokerUnavailable
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	return frame, nil
}

func decodeStorageBrokerFrame(reader io.Reader) (storageBrokerResponse, error) {
	data, err := readStorageBrokerFrame(reader)
	if err != nil {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	var response storageBrokerResponse
	if configjson.Decode(bytes.NewReader(data), &response, storageBrokerMaxFrameBytes, 8, storageBrokerJSONKeys) != nil ||
		!validStorageBrokerResponse(response) {
		return storageBrokerResponse{}, errStorageBrokerUnavailable
	}
	return response, nil
}

func readStorageBrokerFrame(reader io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(reader, header[:]); err != nil {
		return nil, errStorageBrokerUnavailable
	}
	size := binary.BigEndian.Uint32(header[:])
	if size == 0 || size > storageBrokerMaxFrameBytes {
		return nil, errStorageBrokerUnavailable
	}
	data := make([]byte, size)
	if _, err := io.ReadFull(reader, data); err != nil {
		return nil, errStorageBrokerUnavailable
	}
	var trailing [1]byte
	if n, err := reader.Read(trailing[:]); n != 0 || err != io.EOF {
		return nil, errStorageBrokerUnavailable
	}
	return data, nil
}

func validStorageBrokerResponse(response storageBrokerResponse) bool {
	if response.Version != storageBrokerProtocolVersion {
		return false
	}
	switch response.Status {
	case "unavailable", "busy":
		return response.Snapshot == nil && response.GPTObservation == nil
	case "ok":
		if (response.Snapshot == nil) == (response.GPTObservation == nil) {
			return false
		}
		if response.GPTObservation != nil {
			return validStorageGPTObservationSummary(*response.GPTObservation)
		}
		snapshot := response.Snapshot
		if snapshot.SchemaVersion != 2 || snapshot.Scope != "broker-read-only-point-in-time" ||
			!snapshot.InventoryReadOnly || snapshot.ContentRead ||
			snapshot.MutationsPerformed || snapshot.StableIdentityAvailable ||
			snapshot.Observations == nil || len(snapshot.Observations) > maxBlockEntries ||
			snapshot.DeviceCount != len(snapshot.Observations) || snapshot.Limitations == nil ||
			len(snapshot.Limitations) > 32 {
			return false
		}
		type deviceNumber struct{ major, minor uint32 }
		byName := make(map[string]blockObservation, len(snapshot.Observations))
		seenNumbers := make(map[deviceNumber]bool, len(snapshot.Observations))
		wholeDiskCount := 0
		previous := ""
		for _, observation := range snapshot.Observations {
			if !validBlockName(observation.Name) || previous != "" && observation.Name <= previous ||
				(observation.Major == 0 && observation.Minor == 0) || seenNumbers[deviceNumber{observation.Major, observation.Minor}] {
				return false
			}
			previous = observation.Name
			seenNumbers[deviceNumber{observation.Major, observation.Minor}] = true
			byName[observation.Name] = observation
			switch observation.Kind {
			case "block":
				if observation.PartitionNumber != 0 || observation.ParentName != "" ||
					observation.ParentMajor != nil || observation.ParentMinor != nil ||
					!validIdentityStatus(observation.SerialStatus) || !validIdentityStatus(observation.WWNStatus) {
					return false
				}
				wholeDiskCount++
			case "partition":
				if observation.PartitionNumber == 0 || !validBlockName(observation.ParentName) ||
					observation.ParentMajor == nil || observation.ParentMinor == nil ||
					observation.SerialStatus != "" || observation.WWNStatus != "" {
					return false
				}
			default:
				return false
			}
		}
		if snapshot.BlockDevicesOpened && wholeDiskCount == 0 {
			return false
		}
		for _, observation := range snapshot.Observations {
			if observation.Kind != "partition" {
				continue
			}
			parent, exists := byName[observation.ParentName]
			if !exists || parent.Kind != "block" || parent.Major != *observation.ParentMajor ||
				parent.Minor != *observation.ParentMinor {
				return false
			}
		}
		for _, limitation := range snapshot.Limitations {
			if limitation == "" || len(limitation) > 512 {
				return false
			}
		}
		return true
	default:
		return false
	}
}
