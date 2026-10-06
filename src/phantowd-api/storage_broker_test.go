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

func TestStorageBrokerProtocolUsesOnlyFixedOperationsAndRedactedGPTResults(t *testing.T) {
	for _, operation := range []string{storageBrokerOperationInventory, storageBrokerOperationGPT, storageBrokerOperationMDV10} {
		frame, err := encodeStorageBrokerRequest(operation)
		if err != nil {
			t.Fatal("fixed broker operation was rejected", operation)
		}
		request, err := decodeStorageBrokerRequest(bytes.NewReader(frame))
		if err != nil || request.Version != storageBrokerProtocolVersion || request.Operation != operation {
			t.Fatalf("fixed request did not round-trip: %+v %v", request, err)
		}
	}
	if _, err := encodeStorageBrokerRequest("/dev/sda"); err == nil {
		t.Fatal("caller-controlled device request was accepted")
	}
	for _, malformed := range []string{
		`{"version":3,"operation":"observe-gpt","path":"/dev/sda"}`,
		`{"version":3,"version":3,"operation":"observe-gpt"}`,
		`{"version":3,"operation":"mount"}`,
	} {
		if _, err := decodeStorageBrokerRequest(bytes.NewReader(frameJSON(malformed))); err == nil {
			t.Fatal("malformed or arbitrary broker request was accepted", malformed)
		}
	}

	summary := validStorageGPTSummaryForTest()
	response := storageBrokerResponse{Version: storageBrokerProtocolVersion, Status: "ok", GPTObservation: &summary}
	frame, err := encodeStorageBrokerFrame(response)
	if err != nil {
		t.Fatal("valid redacted GPT result was rejected", err)
	}
	decoded, err := decodeStorageBrokerFrame(bytes.NewReader(frame))
	if err != nil || decoded.GPTObservation == nil || decoded.Snapshot != nil ||
		!validStorageGPTObservationSummary(*decoded.GPTObservation) {
		t.Fatalf("redacted GPT result did not round-trip: %+v %v", decoded, err)
	}
	response.Snapshot = validStorageBrokerTestResponse().Snapshot
	if validStorageBrokerResponse(response) {
		t.Fatal("ambiguous response containing both inventory and GPT result was accepted")
	}
}

func TestStorageBrokerCarriesOnlyRedactedMDV10Summary(t *testing.T) {
	operation, err := encodeStorageBrokerRequest(storageBrokerOperationMDV10)
	if err != nil {
		t.Fatal("fixed MD v1.0 observation request was rejected")
	}
	request, err := decodeStorageBrokerRequest(bytes.NewReader(operation))
	if err != nil || request.Operation != storageBrokerOperationMDV10 || request.Version != storageBrokerProtocolVersion {
		t.Fatalf("fixed MD v1.0 operation did not round-trip: %+v %v", request, err)
	}

	summary := validStorageMDV10SummaryForTest()
	response := storageBrokerResponse{Version: storageBrokerProtocolVersion, Status: "ok", MDV10Observation: &summary}
	frame, err := encodeStorageBrokerFrame(response)
	if err != nil {
		t.Fatal("valid redacted MD v1.0 summary was rejected:", err)
	}
	for _, sensitive := range []string{"PHANTOWD-QEMU-MDV10-A", "500f0000", "a19d880f", "/dev/sdb1", "sdb"} {
		if strings.Contains(string(frame), sensitive) {
			t.Fatalf("broker response exposed storage identity %q", sensitive)
		}
	}
	decoded, err := decodeStorageBrokerFrame(bytes.NewReader(frame))
	if err != nil || decoded.MDV10Observation == nil || decoded.Snapshot != nil || decoded.GPTObservation != nil ||
		!validStorageMDV10ObservationSummary(*decoded.MDV10Observation) {
		t.Fatalf("redacted MD v1.0 summary did not round-trip: %+v %v", decoded, err)
	}
	response.GPTObservation = &storageGPTObservationSummary{}
	if validStorageBrokerResponse(response) {
		t.Fatal("ambiguous response containing both MD v1.0 and GPT observations was accepted")
	}
}

func validStorageMDV10SummaryForTest() storageMDV10ObservationSummary {
	return storageMDV10ObservationSummary{
		SchemaVersion: 1, Status: "complete", Scope: "broker-read-only-md-v1.0",
		CandidateDiskCount: 2, GPTDiskCount: 2, RAIDPartitionCount: 2,
		CandidateComponents: 2, MetadataConsistentArrayCount: 1,
		ArrayCount: 1, MetadataActiveRoleCoverageComplete: true,
		BlockMetadataRead: true, MDV10SuperblocksRead: true,
		Limitations: append([]string{}, storageMDV10ObservationLimitations[:]...),
	}
}

func TestStorageMDV10SummaryRejectsIncompleteOrUnsafeClaims(t *testing.T) {
	cases := map[string]func(*storageMDV10ObservationSummary){
		"partial GPT coverage":                 func(s *storageMDV10ObservationSummary) { s.GPTDiskCount-- },
		"unreconciled partition count":         func(s *storageMDV10ObservationSummary) { s.RAIDPartitionCount++ },
		"unidentified member claimed complete": func(s *storageMDV10ObservationSummary) { s.UnidentifiedCandidateComponents = 1 },
		"array counts do not add up":           func(s *storageMDV10ObservationSummary) { s.AmbiguousArrayCount = 1 },
		"coverage claim without consistency":   func(s *storageMDV10ObservationSummary) { s.MetadataConsistentArrayCount = 0 },
		"filesystem data read":                 func(s *storageMDV10ObservationSummary) { s.FilesystemDataRead = true },
		"mount claim":                          func(s *storageMDV10ObservationSummary) { s.MountPerformed = true },
		"mutation claim":                       func(s *storageMDV10ObservationSummary) { s.MutationsPerformed = true },
		"changed fixed limitation":             func(s *storageMDV10ObservationSummary) { s.Limitations[0] = "private path /dev/sdb" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			summary := validStorageMDV10SummaryForTest()
			mutate(&summary)
			if validStorageMDV10ObservationSummary(summary) {
				t.Fatal("unsafe or incomplete MD v1.0 summary was accepted")
			}
		})
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
		"duplicate-key":         frameJSON(`{"version":2,"version":2,"status":"ok","snapshot":{}}`),
		"unknown-key":           frameJSON(`{"version":2,"status":"ok","snapshot":{},"path":"/dev/sda"}`),
		"case-variant-key":      frameJSON(`{"Version":2,"status":"ok","snapshot":{}}`),
		"trailing-document":     append(append([]byte(nil), valid...), []byte(`{}`)...),
		"invalid-snapshot":      frameJSON(`{"version":1,"status":"ok","snapshot":null}`),
		"unavailable-with-data": frameJSON(`{"version":2,"status":"unavailable","snapshot":{}}`),
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
