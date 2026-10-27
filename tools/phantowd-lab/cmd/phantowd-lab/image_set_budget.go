// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"flag"
	"io"
	"strconv"
)

// This comparison concerns recorded counters, never actual allocator capacity.
type extSpaceBudgetReview struct {
	Relation                    string  `json:"relation"`
	RecordedUnreservedFreeBytes *uint64 `json:"recorded_unreserved_free_bytes"`
	RecordedShortfallBytes      *uint64 `json:"recorded_shortfall_bytes"`
	MigrationCapacityQualified  bool    `json:"migration_capacity_qualified"`
}

func parseStorageSpaceArgs(args []string) ([]string, *uint64, error) {
	f := flag.NewFlagSet("inspect-storage-image-set", flag.ContinueOnError)
	f.SetOutput(io.Discard)
	var requested *uint64
	f.Func("required-per-filesystem-bytes", "compare each partition's stored ext counter with this hypothetical byte request", func(text string) error {
		n, err := strconv.ParseUint(text, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != text || requested != nil {
			return errors.New("invalid or repeated byte request")
		}
		requested = &n
		return nil
	})
	if err := f.Parse(args); err != nil || len(f.Args()) < 1 || len(f.Args()) > maxStorageImageSetInputs {
		return nil, nil, errors.New("usage: phantowd-lab inspect-storage-image-set [--required-per-filesystem-bytes UINT64] [--] DISK-IMAGE-1 [DISK-IMAGE-2 [DISK-IMAGE-3 [DISK-IMAGE-4]]]")
	}
	return f.Args(), requested, nil
}

// Called after conflicting-layer counters have been withheld. Reports remain
// per supplied image/partition: no summation, volume identity or admission.
func applyStorageSpaceRequest(result *storageImageSetAssessment, requested *uint64) {
	result.RequestedPerFilesystemBytes = requested
	if requested == nil {
		return
	}
	observations, needsReview := 0, false
	for i := range result.Inputs {
		for j := range result.Inputs[i].PartitionObservations {
			p := &result.Inputs[i].PartitionObservations[j]
			observations++
			p.ExtSpaceBudgetReview = &extSpaceBudgetReview{Relation: "unobserved"}
			if p.ExtSpaceCounters == nil {
				needsReview = true
				continue
			}
			recorded, shortfall := p.ExtSpaceCounters.UnreservedFreeBytes, uint64(0)
			p.ExtSpaceBudgetReview.Relation = "recorded-at-least-requested"
			if recorded < *requested {
				shortfall = *requested - recorded
				p.ExtSpaceBudgetReview.Relation = "recorded-shortfall"
				needsReview = true
			}
			p.ExtSpaceBudgetReview.RecordedUnreservedFreeBytes = &recorded
			p.ExtSpaceBudgetReview.RecordedShortfallBytes = &shortfall
		}
	}
	if needsReview || observations == 0 {
		result.Findings = append(result.Findings, "the caller's per-filesystem byte request has a recorded shortfall or an unobserved counter; allocation and migration remain unqualified")
		if result.Status == "metadata-observed" {
			result.Status = "space-review-required"
		}
	}
}
