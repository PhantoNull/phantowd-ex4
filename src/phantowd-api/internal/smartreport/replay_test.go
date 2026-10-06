//go:build smartreplay

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartreport

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// This opt-in test consumes reports produced in a disposable CPU-only fixture.
// It never runs smartctl or accepts a device path. The normal product is unchanged.
func TestUpstreamReplayCorpus(t *testing.T) {
	root := os.Getenv("PHANTOWD_SMART_REPLAY_CORPUS")
	if root == "" {
		t.Fatal("explicit temporary replay corpus required")
	}
	version := os.Getenv("PHANTOWD_REPLAY_VERSION")
	if version != "7.4" && version != "7.5" {
		t.Fatal("explicit known producer version required")
	}
	cases := []struct {
		name       string
		exit       int
		state      State
		assessment Assessment
	}{
		{"pass", 0, Complete, ReportedPass},
		{"fail", 8, Complete, ReportedFail},
		{"partial-fail", 12, Partial, ReportedFail},
		{"partial-pass", 4, Partial, ReportedPass},
		{"unsupported", 4, UnsupportedSMART, NoAssessment},
		{"disabled", 0, Disabled, NoAssessment},
		{"empty", 2, Unavailable, NoAssessment},
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(cases) {
		t.Fatal("incomplete or extra replay inputs")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.name+".json")
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxBytes {
				t.Fatal("invalid replay input")
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal("cannot read replay input")
			}
			data, readErr := io.ReadAll(io.LimitReader(f, MaxBytes+1))
			closeErr := f.Close()
			if readErr != nil || closeErr != nil || len(data) > MaxBytes {
				t.Fatal("unbounded or unreadable replay input")
			}
			o, err := Parse(data, tc.exit)
			if err != nil || o.State() != tc.state || o.Assessment() != tc.assessment {
				t.Fatalf("unexpected redacted projection: state=%d assessment=%d error=%v", o.State(), o.Assessment(), err)
			}
			var metadata struct {
				Smartctl struct {
					Version []int `json:"version"`
				} `json:"smartctl"`
			}
			if json.Unmarshal(data, &metadata) != nil || len(metadata.Smartctl.Version) != 2 ||
				fmt.Sprintf("%d.%d", metadata.Smartctl.Version[0], metadata.Smartctl.Version[1]) != version {
				t.Fatal("wrong actual producer version")
			}
			if o.Flags().SMARTCommandError != (tc.exit&4 != 0) || o.Flags().FailingStatus != (tc.exit&8 != 0) {
				t.Fatal("collection/failure distinction lost")
			}
		})
	}
}
