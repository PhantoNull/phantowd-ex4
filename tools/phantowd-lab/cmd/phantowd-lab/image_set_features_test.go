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

	"github.com/PhantoNull/phantowd-ex4/phantowd-lab/diskimage"
)

func TestImageSetRequiresReviewForDeclaredExtConstraints(t *testing.T) {
	for _, test := range []struct {
		name   string
		offset int
		bit    uint32
	}{
		{"encryption", 0x60, 0x10000}, {"journal device", 0x60, 8}, {"bigalloc", 0x64, 0x200},
		{"external journal UUID reference", 0xd0, 1}, {"external journal device reference", 0xe4, 1},
		{"unclassified compat", 0x5c, 0x80000000}, {"unclassified incompat", 0x60, 0x80000000}, {"unclassified ro", 0x64, 0x80000000},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := imageSetSpaceFixture()
			binary.LittleEndian.PutUint32(fixture[64*512+1024+test.offset:], test.bit)
			path := filepath.Join(t.TempDir(), "offline.img")
			if err := os.WriteFile(path, fixture, 0o600); err != nil {
				t.Fatal(err)
			}
			var output bytes.Buffer
			code, err := run([]string{"inspect-storage-image-set", path}, &output)
			if err != nil || code != 2 {
				t.Fatalf("feature constraint not held: code=%d err=%v", code, err)
			}
			var report struct {
				SchemaVersion       int    `json:"schema_version"`
				Status              string `json:"status"`
				MigrationAuthorized bool   `json:"migration_authorized"`
				BlockDeviceOpened   bool   `json:"block_device_opened"`
				MutationsPerformed  bool   `json:"mutations_performed"`
				AssemblyPerformed   bool   `json:"assembly_performed"`
				MountPerformed      bool   `json:"mount_performed"`
				Inputs              []struct {
					PartitionObservations []struct {
						ExtFeatureReview *diskimage.ExtFeatureReview `json:"ext_feature_review"`
						ExtSpaceCounters *diskimage.ExtSpaceCounters `json:"ext_space_counters"`
					} `json:"partition_observations"`
				} `json:"inputs"`
			}
			if err := json.Unmarshal(output.Bytes(), &report); err != nil {
				t.Fatal(err)
			}
			if report.SchemaVersion != 6 || report.Status != "incomplete" || report.MigrationAuthorized || len(report.Inputs) != 1 || len(report.Inputs[0].PartitionObservations) != 1 {
				t.Fatalf("unsafe report: %s", output.String())
			}
			partition := report.Inputs[0].PartitionObservations[0]
			if partition.ExtFeatureReview == nil || !partition.ExtFeatureReview.Required || partition.ExtSpaceCounters == nil || partition.ExtSpaceCounters.MigrationCapacityQualified {
				t.Fatalf("missing feature review: %s", output.String())
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, fixture) || report.BlockDeviceOpened || report.MutationsPerformed || report.AssemblyPerformed || report.MountPerformed {
				t.Fatal("observation modified source or acquired authority", err)
			}
		})
	}
}
