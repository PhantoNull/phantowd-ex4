//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"strings"
	"testing"
)

func TestNFSTableOutputRequiresExactPopulatedAndEmptyControls(t *testing.T) {
	// Actual pinned exportfs output without /proc/export_features uses the old
	// secinfo mask, which does not render the candidate's explicit secure flag.
	const table = "/srv/phantowd/volumes/bulk/books  127.0.0.1/32(sync,wdelay,hide,fsid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,mountpoint=/srv/phantowd/volumes/bulk,anonuid=1000,anongid=1000,sec=sys,rw,root_squash,all_squash)\n"
	if !nfsTableOutputQEMU([]byte(table), true) || !nfsTableOutputQEMU(nil, false) {
		t.Fatal("exact synthetic table/empty control refused")
	}
	for _, output := range []string{"", table + table, strings.TrimSuffix(table, "\n"),
		strings.ReplaceAll(table, "127.0.0.1/32", "127.0.0.2/32"),
		strings.ReplaceAll(table, "root_squash", "no_root_squash"),
		strings.ReplaceAll(table, "anonuid=1000", "anonuid=0"),
		strings.ReplaceAll(table, "sec=sys", "sec=sys,unknown"),
		strings.ReplaceAll(table, "sec=sys", "sec=sys,secure"), table + "warning\n"} {
		if nfsTableOutputQEMU([]byte(output), true) {
			t.Fatal("incomplete, broadened or unrelated table admitted")
		}
	}
	if nfsTableOutputQEMU([]byte(table), false) || nfsTableOutputQEMU([]byte("\n"), false) {
		t.Fatal("nonempty control admitted")
	}
}
