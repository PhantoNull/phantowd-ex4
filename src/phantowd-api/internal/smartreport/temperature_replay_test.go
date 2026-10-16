//go:build smartreplay

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartreport

import (
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// Separate from the original seven info+health reports. The actual generic
// producer is invoked externally on invented attribute bytes, never by Go.
func TestUpstreamTemperatureCorpus(t *testing.T) {
	root := os.Getenv("PHANTOWD_SMART_TEMPERATURE_CORPUS")
	version := os.Getenv("PHANTOWD_REPLAY_VERSION")
	if root == "" || (version != "7.4" && version != "7.5") {
		t.Fatal("explicit temporary temperature corpus and producer version required")
	}
	cases := []struct {
		name     string
		value    int16
		reported bool
	}{
		{"reported", 37, true},
		{"zero-omitted", 0, false},
		{"upper", 127, true},
		{"invalid-omitted", 0, false},
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != len(cases) {
		t.Fatal("incomplete or extra temperature inputs")
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(root, tc.name+".json")
			info, err := os.Lstat(path)
			if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > MaxBytes {
				t.Fatal("invalid temperature input")
			}
			f, err := os.Open(path)
			if err != nil {
				t.Fatal("cannot read temperature input")
			}
			data, readErr := io.ReadAll(io.LimitReader(f, MaxBytes+1))
			closeErr := f.Close()
			if readErr != nil || closeErr != nil || len(data) > MaxBytes {
				t.Fatal("unbounded or unreadable temperature input")
			}
			o, err := ParseATATemperature(data, 0)
			value, reported := o.ReportedCelsius()
			health, healthErr := Parse(data, 0)
			if err != nil || healthErr != nil || value != tc.value || reported != tc.reported || o.Health() != health || health.State() != Complete || health.Assessment() != ReportedPass {
				t.Fatal("actual producer temperature or health mismatch", err)
			}
			var metadata struct {
				Smartctl struct{ Version []int }
			}
			if json.Unmarshal(data, &metadata) != nil || len(metadata.Smartctl.Version) != 2 || metadata.Smartctl.Version[0] != 7 || metadata.Smartctl.Version[1] != int(version[2]-'0') {
				t.Fatal("wrong actual temperature producer version")
			}
		})
	}
}
