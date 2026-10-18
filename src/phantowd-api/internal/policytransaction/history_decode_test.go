// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func TestDecodedHistoryNamesAndFailureCleanup(t *testing.T) {
	anchor, current, operations, _ := bundleHistoryFixture(t)
	names := []string{bundleHistoryName(t, operations[0].Data), bundleHistoryName(t, operations[1].Data)}
	for _, tc := range []struct {
		names []string
		ops   []policyevidence.Slot
	}{
		{names[:1], operations}, {[]string{"x", names[1]}, operations},
		{[]string{names[0], names[0]}, operations},
		{names, []policyevidence.Slot{operations[0], {State: policyevidence.Present, Data: []byte(`{}`)}}},
		{[]string{names[1], names[0]}, operations},
	} {
		d, err := decodeBundleHistory(anchor, current, tc.ops, tc.names)
		if err != ErrInvalid || len(d.bundles) != 0 || len(d.entries) != 0 {
			t.Fatal("invalid history returned owned/partial data")
		}
	}
	d, err := decodeBundleHistory(anchor, current, operations, names)
	if err != nil || len(d.bundles) != 2 || len(d.entries) != 2 {
		t.Fatal("valid decoded history refused")
	}
	retained := d.entries[0].Base.Data
	d.clear()
	for _, value := range retained {
		if value != 0 {
			t.Fatal("owned decoded bytes not cleared")
		}
	}
	if d.bundles != nil || d.entries != nil {
		t.Fatal("decoded data references retained after clear")
	}
}
