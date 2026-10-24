// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestImageSetReportsPartitionSpaceWithoutMigrationCapacity(t *testing.T) {
	fixture := imageSetSpaceFixture()
	path := filepath.Join(t.TempDir(), "offline.img")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-storage-image-set", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v output=%s", code, err, output.String())
	}
	var report struct {
		Schema     int  `json:"schema_version"`
		Authorized bool `json:"migration_authorized"`
		Inputs     []struct {
			Index      int `json:"input_index"`
			Partitions []struct {
				Number int `json:"partition_number"`
				Space  *struct {
					FreeBytes       uint64 `json:"free_bytes"`
					ReservedBytes   uint64 `json:"reserved_bytes"`
					UnreservedBytes uint64 `json:"unreserved_free_bytes"`
					Qualified       bool   `json:"migration_capacity_qualified"`
				} `json:"ext_space_counters"`
			} `json:"partition_observations"`
		} `json:"inputs"`
	}
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Schema != 5 || report.Authorized || len(report.Inputs) != 1 || report.Inputs[0].Index != 1 || len(report.Inputs[0].Partitions) != 1 {
		t.Fatalf("unexpected set report: %s", output.String())
	}
	partition := report.Inputs[0].Partitions[0]
	if partition.Number != 1 || partition.Space == nil || partition.Space.FreeBytes != 8192 ||
		partition.Space.ReservedBytes != 4096 || partition.Space.UnreservedBytes != 4096 || partition.Space.Qualified {
		t.Fatalf("recorded partition counters missing or admitted: %s", output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, fixture) {
		t.Fatal("source image modified", err)
	}
}

func TestImageSetWithholdsSpaceWhenSourceIsUnknownOrLayerConflicts(t *testing.T) {
	for _, test := range []struct {
		name    string
		fixture func() []byte
		code    int
		status  string
	}{
		{name: "no ext superblock", fixture: func() []byte {
			image := imageSetSpaceFixture()
			image[64*512+1024+56] = 0
			return image
		}, status: "metadata-observed"},
		{name: "invalid reserved counters", fixture: func() []byte {
			image := imageSetSpaceFixture()
			binary.LittleEndian.PutUint32(image[64*512+1024+8:], 33)
			return image
		}, code: 2, status: "incomplete"},
		{name: "ext and MD v1.2 signatures", fixture: syntheticGPTImageForCommand, code: 2, status: "ambiguous"},
		{name: "ext and MD v1.0 signatures", fixture: func() []byte {
			image := syntheticGPTImageForMDV10Member(0, 0, 41)
			putExtSuperblockForCommand(image)
			return image
		}, code: 2, status: "ambiguous"},
		{name: "ext and MD v0.90 signatures", fixture: func() []byte {
			image := syntheticGPTImageWithMDV090()
			copy(image[64*512+1024:64*512+2048], imageSetSpaceFixture()[64*512+1024:64*512+2048])
			return image
		}, code: 2, status: "ambiguous"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := test.fixture()
			path := filepath.Join(t.TempDir(), "offline.img")
			if err := os.WriteFile(path, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			code, err := run([]string{"inspect-storage-image-set", path}, &output)
			if err != nil || code != test.code {
				t.Fatalf("code=%d err=%v", code, err)
			}
			var report storageImageSetAssessment
			if err := json.Unmarshal(output.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.Status != test.status || report.MigrationAuthorized || len(report.Inputs) != 1 || len(report.Inputs[0].PartitionObservations) != 1 ||
				report.Inputs[0].PartitionObservations[0].ExtSpaceCounters != nil || !bytes.Contains(output.Bytes(), []byte(`"ext_space_counters": null`)) {
				t.Fatalf("unknown or conflicting source published usable counters: %s", output.String())
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, fixture) {
				t.Fatal("source image modified", err)
			}
		})
	}
}

func TestImageSetKeepsDuplicateImagesSeparateAndRequiresReview(t *testing.T) {
	fixtures := [][]byte{imageSetSpaceFixture(), imageSetSpaceFixture()}
	binary.LittleEndian.PutUint32(fixtures[1][64*512+1024+12:], 16)
	args := []string{"inspect-storage-image-set"}
	for _, fixture := range fixtures {
		path := filepath.Join(t.TempDir(), "offline.img")
		if err := os.WriteFile(path, fixture, 0o600); err != nil {
			t.Fatal(err)
		}
		args = append(args, path)
	}
	var output bytes.Buffer
	code, err := run(args, &output)
	if err != nil || code != 2 {
		t.Fatalf("duplicate images: code=%d err=%v", code, err)
	}
	var report storageImageSetAssessment
	if err := json.Unmarshal(output.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.Status != "ambiguous" || report.MigrationAuthorized || len(report.Inputs) != 2 || report.IdentityScan == nil ||
		report.IdentityScan.DuplicateFilesystemUUIDGroups != 1 {
		t.Fatalf("duplicates admitted: %s", output.String())
	}
	for index, input := range report.Inputs {
		if input.InputIndex != index+1 || len(input.PartitionObservations) != 1 {
			t.Fatalf("ordinal lost: %+v", input)
		}
		space := input.PartitionObservations[0].ExtSpaceCounters
		if space == nil || space.FreeBytes != uint64(8*(index+1))*1024 || space.ReservedBytes != 4096 || space.MigrationCapacityQualified {
			t.Fatalf("counters lost their input or became qualified: %+v", space)
		}
		after, err := os.ReadFile(args[index+1])
		if err != nil || !bytes.Equal(after, fixtures[index]) {
			t.Fatal("source image modified", err)
		}
	}
	for _, private := range append(args[1:], "SPACE-SET-SAMPLE") {
		if bytes.Contains(output.Bytes(), []byte(filepath.ToSlash(private))) {
			t.Fatal("path or raw identity leaked")
		}
	}
}

func imageSetSpaceFixture() []byte {
	image := syntheticGPTImageWithMDV090()
	clear(image[64*512 : 1985*512])
	sb := image[64*512+1024 : 64*512+2048]
	binary.LittleEndian.PutUint32(sb[0:4], 32)
	binary.LittleEndian.PutUint32(sb[4:8], 32)
	binary.LittleEndian.PutUint32(sb[8:12], 4)
	binary.LittleEndian.PutUint32(sb[12:16], 8)
	binary.LittleEndian.PutUint32(sb[20:24], 1)
	binary.LittleEndian.PutUint32(sb[32:36], 32)
	binary.LittleEndian.PutUint32(sb[40:44], 32)
	binary.LittleEndian.PutUint16(sb[56:58], 0xef53)
	binary.LittleEndian.PutUint16(sb[58:60], 1)
	binary.LittleEndian.PutUint32(sb[76:80], 1)
	copy(sb[104:120], []byte("SPACE-SET-SAMPLE"))
	return image
}
