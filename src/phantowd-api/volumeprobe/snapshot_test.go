// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"reflect"
	"strings"
	"testing"
)

func TestSnapshotMatch(t *testing.T) {
	result, err := decode(strings.NewReader(validResult))
	if err != nil {
		t.Fatal(err)
	}
	a := objectKey{kind: "block-device", rawDevice: 1}
	b := objectKey{kind: "block-device", rawDevice: 2}
	for _, test := range []struct {
		name, state string
		entries     []observation
		indices     []int
	}{
		{"empty", "not-observed", []observation{}, []int{}},
		{"single", "one-object", []observation{{result, a}}, []int{0}},
		{"alias", "one-object", []observation{{result, a}, {result, a}}, []int{0, 1}},
		{"clone", "conflicting-objects", []observation{{result, a}, {result, b}, {result, a}}, []int{0, 1, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			snapshot, err := makeSnapshot(test.entries)
			if err != nil {
				t.Fatal(err)
			}
			match, err := snapshot.MatchUUID(result.FilesystemUUID)
			if err != nil || match.State != test.state || !reflect.DeepEqual(match.SourceIndices, test.indices) {
				t.Fatalf("match: %+v %v", match, err)
			}
			missing, err := snapshot.MatchUUID("11111111-2222-3333-4444-555555555555")
			if err != nil || missing.State != "not-observed" || len(missing.SourceIndices) != 0 {
				t.Fatal(missing, err)
			}
			copy := snapshot.Results()
			if len(copy) > 0 {
				copy[0] = Result{}
				if snapshot.Results()[0] != result {
					t.Fatal("mutable results")
				}
			}
		})
	}
	if _, err := (Snapshot{}).MatchUUID("not-an-uuid"); err == nil {
		t.Fatal("invalid query")
	}
	different := result
	different.FilesystemUUID = "11111111-2222-3333-4444-555555555555"
	if snapshot, err := makeSnapshot([]observation{{result, a}, {different, a}}); err == nil || len(snapshot.Results()) != 0 {
		t.Fatal("inconsistent same-object result")
	}
}
