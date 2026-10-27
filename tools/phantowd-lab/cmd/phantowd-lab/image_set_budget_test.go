// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestImageSetRequestedSpaceBudgetComparesRecordedCounters(t *testing.T) {
	image := imageSetSpaceFixture()
	path := filepath.Join(t.TempDir(), "synthetic.img")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-storage-image-set", "--required-per-filesystem-bytes", "4096", path}, &output)
	if err != nil || code != 0 {
		t.Fatal("recorded space comparison unavailable", code, err, output.String())
	}
	var report struct {
		Schema     int     `json:"schema_version"`
		Requested  *uint64 `json:"requested_per_filesystem_bytes"`
		Authorized bool    `json:"migration_authorized"`
		Inputs     []struct {
			Partitions []struct {
				Budget *struct {
					Relation  string  `json:"relation"`
					Recorded  *uint64 `json:"recorded_unreserved_free_bytes"`
					Shortfall *uint64 `json:"recorded_shortfall_bytes"`
					Qualified bool    `json:"migration_capacity_qualified"`
				} `json:"ext_space_budget_review"`
			} `json:"partition_observations"`
		} `json:"inputs"`
	}
	if json.Unmarshal(output.Bytes(), &report) != nil || report.Schema != 6 || report.Requested == nil || *report.Requested != 4096 || report.Authorized || len(report.Inputs) != 1 || len(report.Inputs[0].Partitions) != 1 {
		t.Fatal("invalid bounded space review", output.String())
	}
	b := report.Inputs[0].Partitions[0].Budget
	if b == nil || b.Relation != "recorded-at-least-requested" || b.Recorded == nil || *b.Recorded != 4096 || b.Shortfall == nil || *b.Shortfall != 0 || b.Qualified {
		t.Fatal("metadata comparison inferred capacity or lost exact counters", output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, image) {
		t.Fatal("source image changed", err)
	}
}

func TestImageSetSpaceRequestExactArithmeticAndKnownZero(t *testing.T) {
	for _, tc := range []struct {
		request             string
		zero                bool
		code                int
		relation            string
		recorded, shortfall uint64
	}{
		{"0", true, 0, "recorded-at-least-requested", 0, 0},
		{"4097", false, 2, "recorded-shortfall", 4096, 1},
		{"18446744073709551615", false, 2, "recorded-shortfall", 4096, 18446744073709547519},
	} {
		t.Run(tc.request, func(t *testing.T) {
			image := imageSetSpaceFixture()
			if tc.zero {
				binary.LittleEndian.PutUint32(image[64*512+1024+12:], 0)
			}
			path := filepath.Join(t.TempDir(), "synthetic.img")
			if err := os.WriteFile(path, image, 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			code, err := run([]string{"inspect-storage-image-set", "--required-per-filesystem-bytes", tc.request, path}, &out)
			var report storageImageSetAssessment
			if err != nil || code != tc.code || json.Unmarshal(out.Bytes(), &report) != nil || report.RequestedPerFilesystemBytes == nil || report.MigrationAuthorized {
				t.Fatal(code, err, out.String())
			}
			b := report.Inputs[0].PartitionObservations[0].ExtSpaceBudgetReview
			if b == nil || b.Relation != tc.relation || b.RecordedUnreservedFreeBytes == nil || *b.RecordedUnreservedFreeBytes != tc.recorded || b.RecordedShortfallBytes == nil || *b.RecordedShortfallBytes != tc.shortfall || b.MigrationCapacityQualified {
				t.Fatal("lost zero or overflowed metadata subtraction", out.String())
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, image) {
				t.Fatal("input changed", err)
			}
		})
	}
}

func TestImageSetSpaceRequestPreservesUnknownAndExistingReview(t *testing.T) {
	for _, tc := range []struct {
		name             string
		image            func() []byte
		status, relation string
		known            bool
	}{
		{"absent ext", func() []byte { b := imageSetSpaceFixture(); b[64*512+1024+56] = 0; return b }, "space-review-required", "unobserved", false},
		{"invalid counters", func() []byte {
			b := imageSetSpaceFixture()
			binary.LittleEndian.PutUint32(b[64*512+1024+8:], 33)
			return b
		}, "incomplete", "unobserved", false},
		{"conflicting ext MD", syntheticGPTImageForCommand, "ambiguous", "unobserved", false},
		{"dirty ext", func() []byte {
			b := imageSetSpaceFixture()
			binary.LittleEndian.PutUint16(b[64*512+1024+58:], 0)
			return b
		}, "incomplete", "recorded-at-least-requested", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			image := tc.image()
			path := filepath.Join(t.TempDir(), "synthetic.img")
			if err := os.WriteFile(path, image, 0600); err != nil {
				t.Fatal(err)
			}
			var out bytes.Buffer
			code, err := run([]string{"inspect-storage-image-set", "--required-per-filesystem-bytes", "0", path}, &out)
			var report storageImageSetAssessment
			if err != nil || code != 2 || json.Unmarshal(out.Bytes(), &report) != nil || report.Status != tc.status || report.MigrationAuthorized || report.BlockDeviceOpened || report.MountPerformed || report.MutationsPerformed {
				t.Fatal("byte request erased a refusal", code, err, out.String())
			}
			b := report.Inputs[0].PartitionObservations[0].ExtSpaceBudgetReview
			if b == nil || b.Relation != tc.relation || (b.RecordedUnreservedFreeBytes != nil) != tc.known || (b.RecordedShortfallBytes != nil) != tc.known || b.MigrationCapacityQualified {
				t.Fatal("unobserved counter became observed zero", out.String())
			}
			after, err := os.ReadFile(path)
			if err != nil || !bytes.Equal(after, image) {
				t.Fatal("input changed", err)
			}
		})
	}
}

func TestImageSetSpaceRequestRejectsAmbiguousArgumentsBeforeReading(t *testing.T) {
	for _, text := range []string{"", "00", "+1", "-1", " 1", "1.0", "18446744073709551616", "PRIVATE-SENTINEL"} {
		var output bytes.Buffer
		code, err := run([]string{"inspect-storage-image-set", "--required-per-filesystem-bytes", text, "missing-private-image"}, &output)
		if code != 1 || err == nil || output.Len() != 0 || !strings.HasPrefix(err.Error(), "usage:") || strings.Contains(err.Error(), "PRIVATE-SENTINEL") || strings.Contains(err.Error(), "missing-private-image") {
			t.Fatal("bad argument reached image I/O or echoed input", code, err, output.String())
		}
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-storage-image-set", "--required-per-filesystem-bytes", "0", "--required-per-filesystem-bytes", "1", "missing-private-image"}, &output)
	if code != 1 || err == nil || output.Len() != 0 || !strings.HasPrefix(err.Error(), "usage:") {
		t.Fatal(code, err)
	}
}

func TestImageSetSpaceRequestIsExplicitAndNeverAggregatesImages(t *testing.T) {
	image := imageSetSpaceFixture()
	var paths []string
	for i := 0; i < 2; i++ {
		path := filepath.Join(t.TempDir(), "synthetic.img")
		if err := os.WriteFile(path, image, 0600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	var output bytes.Buffer
	code, err := run(append([]string{"inspect-storage-image-set"}, paths...), &output)
	var report storageImageSetAssessment
	if err != nil || code != 2 || json.Unmarshal(output.Bytes(), &report) != nil || report.Status != "ambiguous" || report.RequestedPerFilesystemBytes != nil {
		t.Fatal("default request changed", code, err, output.String())
	}
	for _, input := range report.Inputs {
		if input.PartitionObservations[0].ExtSpaceBudgetReview != nil {
			t.Fatal("omitted request became observed zero")
		}
	}
	output.Reset()
	code, err = run(append([]string{"inspect-storage-image-set", "--required-per-filesystem-bytes", "8192"}, paths...), &output)
	if err != nil || code != 2 || json.Unmarshal(output.Bytes(), &report) != nil || report.Status != "ambiguous" || report.MigrationAuthorized {
		t.Fatal("byte request erased duplicate identity review", code, err, output.String())
	}
	for _, input := range report.Inputs {
		b := input.PartitionObservations[0].ExtSpaceBudgetReview
		if b == nil || b.Relation != "recorded-shortfall" || b.RecordedUnreservedFreeBytes == nil || *b.RecordedUnreservedFreeBytes != 4096 || b.RecordedShortfallBytes == nil || *b.RecordedShortfallBytes != 4096 || b.MigrationCapacityQualified {
			t.Fatal("separate input counters were added or admitted", output.String())
		}
	}
	for _, path := range paths {
		after, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(after, image) {
			t.Fatal("input changed", err)
		}
	}
}
