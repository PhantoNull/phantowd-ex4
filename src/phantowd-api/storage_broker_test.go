// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"
)

func validStorageBrokerTestResponse() storageBrokerResponse {
	return storageBrokerResponse{
		Version: storageBrokerProtocolVersion,
		Status:  "ok",
		Snapshot: &storageSnapshot{
			SchemaVersion:           2,
			Scope:                   "broker-read-only-point-in-time",
			InventoryReadOnly:       true,
			BlockDevicesOpened:      false,
			StableIdentityAvailable: false,
			Observations:            []blockObservation{},
			Limitations:             []string{},
		},
	}
}

func TestStorageBrokerFrameRoundTripIsBoundedAndRedacted(t *testing.T) {
	response := validStorageBrokerTestResponse()
	response.Snapshot.DeviceCount = 1
	response.Snapshot.Observations = []blockObservation{{
		Name: "sda", Kind: "block", Major: 8, Minor: 0, SizeBytes: 1024,
		SerialStatus: identityPresent, WWNStatus: identityPresent,
		serialEvidence: [32]byte{'s'}, wwnEvidence: [32]byte{'w'},
		diskSequence: 78, sysfsTarget: "devices/platform/ata/host0/target0:0:0/0:0:0:0/block/sda",
	}}
	frame, err := encodeStorageBrokerFrame(response)
	if err != nil {
		t.Fatal("valid broker response was rejected")
	}
	if int(binary.BigEndian.Uint32(frame[:4])) != len(frame)-4 || strings.Contains(string(frame), "serialEvidence") ||
		strings.Contains(string(frame), "sysfsTarget") || strings.Contains(string(frame), "diskSequence") {
		t.Fatal("broker frame length or redaction was invalid")
	}
	got, err := decodeStorageBrokerFrame(bytes.NewReader(frame))
	if err != nil || got.Status != "ok" || got.Snapshot.DeviceCount != 1 || got.Snapshot.Observations[0].Name != "sda" {
		t.Fatal("valid broker response did not round-trip")
	}
}

func TestStorageBrokerResponseValidatesPublicPartitionTopology(t *testing.T) {
	response := validStorageBrokerTestResponse()
	response.Snapshot.DeviceCount = 2
	response.Snapshot.BlockDevicesOpened = true
	parentMajor, parentMinor := uint32(8), uint32(0)
	response.Snapshot.Observations = []blockObservation{
		{Name: "sda", Kind: "block", Major: 8, Minor: 0, SizeBytes: 4096, SerialStatus: identityUnavailable, WWNStatus: identityUnavailable},
		{Name: "sda1", Kind: "partition", Major: 8, Minor: 1, SizeBytes: 2048, PartitionNumber: 1, ParentName: "sda", ParentMajor: &parentMajor, ParentMinor: &parentMinor},
	}
	if !validStorageBrokerResponse(response) {
		t.Fatal("valid public partition-parent topology was rejected")
	}
	response.Snapshot.Observations[1].ParentMajor = new(uint32)
	if validStorageBrokerResponse(response) {
		t.Fatal("partition whose parent major disagrees with the inventory was accepted")
	}
}

func TestStorageBrokerFrameRejectsMalformedAndAmbiguousJSON(t *testing.T) {
	valid, err := encodeStorageBrokerFrame(validStorageBrokerTestResponse())
	if err != nil {
		t.Fatal("test response was invalid")
	}
	cases := map[string][]byte{
		"short-header":          {0, 1, 2},
		"zero-length":           {0, 0, 0, 0},
		"oversized":             {0, 1, 0, 1},
		"truncated-body":        append([]byte{0, 0, 0, 10}, []byte(`{"x":`)...),
		"duplicate-key":         frameJSON(`{"version":1,"version":1,"status":"ok","snapshot":{}}`),
		"unknown-key":           frameJSON(`{"version":1,"status":"ok","snapshot":{},"path":"/dev/sda"}`),
		"case-variant-key":      frameJSON(`{"Version":1,"status":"ok","snapshot":{}}`),
		"trailing-document":     append(append([]byte(nil), valid...), []byte(`{}`)...),
		"invalid-snapshot":      frameJSON(`{"version":1,"status":"ok","snapshot":null}`),
		"unavailable-with-data": frameJSON(`{"version":1,"status":"unavailable","snapshot":{}}`),
	}
	for name, frame := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeStorageBrokerFrame(bytes.NewReader(frame)); err == nil {
				t.Fatal("invalid broker frame was accepted")
			}
		})
	}
}

func TestStorageBrokerResponseRequiresReadOnlyPointInTimeSnapshot(t *testing.T) {
	base := validStorageBrokerTestResponse()
	tests := []struct {
		name   string
		change func(*storageBrokerResponse)
	}{
		{"wrong-version", func(response *storageBrokerResponse) { response.Version++ }},
		{"missing-snapshot", func(response *storageBrokerResponse) { response.Snapshot = nil }},
		{"content-read", func(response *storageBrokerResponse) { response.Snapshot.ContentRead = true }},
		{"mutated", func(response *storageBrokerResponse) { response.Snapshot.MutationsPerformed = true }},
		{"stable-identity-overclaim", func(response *storageBrokerResponse) { response.Snapshot.StableIdentityAvailable = true }},
		{"count-mismatch", func(response *storageBrokerResponse) { response.Snapshot.DeviceCount = 1 }},
		{"nil-observations", func(response *storageBrokerResponse) { response.Snapshot.Observations = nil }},
		{"wrong-scope", func(response *storageBrokerResponse) { response.Snapshot.Scope = "inventory" }},
		{"unavailable-with-snapshot", func(response *storageBrokerResponse) { response.Status = "unavailable" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			response := base
			snapshot := *base.Snapshot
			snapshot.Observations = append([]blockObservation{}, snapshot.Observations...)
			snapshot.Limitations = append([]string{}, snapshot.Limitations...)
			response.Snapshot = &snapshot
			test.change(&response)
			if validStorageBrokerResponse(response) {
				t.Fatal("invalid response contract was accepted")
			}
		})
	}
}

func frameJSON(data string) []byte {
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(data)))
	copy(frame[4:], data)
	return frame
}
