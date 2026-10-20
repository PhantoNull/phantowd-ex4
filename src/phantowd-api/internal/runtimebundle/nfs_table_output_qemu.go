//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

// Exact pinned exportfs -s rendering of this ONE synthetic candidate. This is
// not a general exports parser, kernel observation or product policy admission.
// With no /proc export_features, the pinned old secinfo mask omits secure;
// the listing cannot independently attest that option or kernel enforcement.
func nfsTableOutputQEMU(output []byte, populated bool) bool {
	if !populated {
		return len(output) == 0
	}
	return string(output) == "/srv/phantowd/volumes/bulk/books  127.0.0.1/32(sync,wdelay,hide,fsid=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee,mountpoint=/srv/phantowd/volumes/bulk,anonuid=1000,anongid=1000,sec=sys,rw,root_squash,all_squash)\n"
}
