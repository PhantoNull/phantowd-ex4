// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "testing"

func TestAccountStartupRefusesAmbiguousOrNoncanonicalDescriptorSources(t *testing.T) {
	for _, tc := range []struct{ dir, slot string }{
		{"configured-path", "3"}, {"", "03"}, {"", "0"}, {"", "4"},
		{"", "-1"}, {"", " 3"}, {"", "/proc/self/fd/3"}, {"", ""},
	} {
		s, err := openConfiguredAccountStore(tc.dir, tc.slot)
		if s != nil {
			s.Close()
		}
		if err == nil {
			t.Fatalf("unsafe startup source accepted: %q %q", tc.dir, tc.slot)
		}
	}
}
