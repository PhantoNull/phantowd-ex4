//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner_test

import (
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

func TestNFSSourceMountdStartupRequiresExactRoleAndCompleteNotice(t *testing.T) {
	wanted := []byte("PHANTOWD_NFS_SOURCE_MOUNTD_HANDOFF private_view=true caps=dac-read-search channels=3 sources=3 filehandle=true active_interfaces=lo fixed_mountd=true\nrpc.mountd: Version 2.8.6 starting\n")
	for i := 0; i <= len(wanted); i++ {
		ready, err := processowner.NFSSourceMountdStartupReadyQEMU(wanted[:i])
		if err != nil || ready != (i == len(wanted)) {
			t.Fatal("partial notice incorrectly classified", i, err)
		}
	}
	for _, data := range [][]byte{[]byte("PHANTOWD_NFS_MOUNTD_HANDOFF"), append(append([]byte{}, wanted...), 'x'), []byte("rpc.mountd: warning\n")} {
		if ready, err := processowner.NFSSourceMountdStartupReadyQEMU(data); err == nil || ready {
			t.Fatal("foreign stream admitted")
		}
	}
}

func TestNFSSourceMountdAccessRequiresExactCompleteTranscript(t *testing.T) {
	start := "PHANTOWD_NFS_SOURCE_MOUNTD_HANDOFF private_view=true caps=dac-read-search channels=3 sources=3 filehandle=true active_interfaces=lo fixed_mountd=true\nrpc.mountd: Version 2.8.6 starting\n"
	base := "/srv/phantowd/volumes/qemu-plan/"
	book := "rpc.mountd: authenticated mount request from 127.0.0.1:933 for " + base + "books (" + base + "books)\n"
	archive := "rpc.mountd: authenticated mount request from 127.0.0.1:958 for " + base + "archive (" + base + "archive)\n"
	denied := "rpc.mountd: refused mount request from 127.0.0.1 for " + base + "denied (/): not exported\n"
	wanted := start + book + archive + denied
	stop := "rpc.mountd: Caught signal 15, un-registering and exiting.\n"
	for _, stopped := range []bool{false, true} {
		value := wanted
		if stopped {
			value += stop
		}
		if err := processowner.NFSSourceMountdAccessHandoffQEMU([]byte(value), stopped); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < len(value); i++ {
			if processowner.NFSSourceMountdAccessHandoffQEMU([]byte(value[:i]), stopped) == nil {
				t.Fatal("partial stream accepted", i)
			}
		}
	}
	for _, value := range []string{start, wanted + "x", start + archive + book + denied, wanted + denied, wanted + stop,
		strings.ReplaceAll(wanted, ":933 ", ":0933 "), strings.ReplaceAll(wanted, ":933 ", ":1024 "), strings.ReplaceAll(wanted, ":933 ", ":0 "),
		strings.ReplaceAll(wanted, "127.0.0.1", "192.0.2.1"), strings.ReplaceAll(wanted, "not exported", "unmatched host"),
		start + book + "rpc.mountd: can't open /run/nfs/rmtab for writing\n" + archive + denied} {
		if processowner.NFSSourceMountdAccessHandoffQEMU([]byte(value), false) == nil {
			t.Fatal("foreign stream accepted", value)
		}
	}
}
