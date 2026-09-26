//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"runtime"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const qemuNFSVolumeUUID = "11111111-2222-3333-4444-555555555555"
const qemuNFSWritablePath = `RW #1 "quoted"`

// Fixed synthetic inputs only: no caller-selected paths, policy, or commands.
// This renderer does not install exports; the guest-only shell harness does.
func qemuNFSFixture() (nfsconfig.Preview, error) {
	volumes := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "qemu-only", FilesystemUUID: qemuNFSVolumeUUID}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}}
	policy := nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
		Exports: []nfsconfig.Export{}}
	for i, spec := range []struct{ path, access, network string }{
		{qemuNFSWritablePath, "rw", "127.0.0.1/32"},
		{"read-only", "ro", "127.0.0.1/32"},
		{"denied-client", "rw", "192.0.2.1/32"},
	} {
		policy.Exports = append(policy.Exports, nfsconfig.Export{
			ID: fmt.Sprintf("aaaaaaaa-bbbb-cccc-dddd-%012d", i+1), VolumeID: "qemu-only", RelativePath: spec.path,
			Clients: []nfsconfig.Client{{Network: spec.network, Access: spec.access, Squash: "all",
				AnonymousUID: 101000, AnonymousGID: 101000, Security: "sys"}}})
	}
	return nfsconfig.Build(policy, volumes)
}

func runQEMUNFSTest(mode string) error {
	switch mode {
	case "exports", "io", "mount-rw", "mount-ro", "guard", "denied-client", "verify-disk":
	default:
		return errors.New("unknown QEMU NFS fixture mode")
	}
	// Guard this test's fixed paths against accidental developer-host use.
	// The release/profile guard in the shell is additional, not authorization
	// to run this fixture on a physical NAS.
	if runtime.GOOS != "linux" || runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" {
		return errors.New("NFS fixture requires ARMv5 QEMU")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("NFS fixture requires the Versatile PB development machine")
	}
	if mode == "io" {
		return exerciseQEMUNFSIO()
	}
	if mode == "verify-disk" {
		return verifyQEMUNFSDevice(os.DirFS("/sys"))
	}
	if mode != "exports" {
		return exerciseQEMUNFSMount(mode)
	}
	preview, err := qemuNFSFixture()
	if err != nil {
		return err
	}
	_, err = fmt.Fprint(os.Stdout, preview.Table)
	return err
}

func verifyQEMUNFSDevice(sysfs fs.FS) error {
	serialPage, serialStatus := readSCSVPDPage(sysfs, "class/block/sdb/device/vpd_pg80", 0x80)
	serial, valid := vpdPayload(serialPage, 0x80)
	wwnPage, wwnStatus := readSCSVPDPage(sysfs, "class/block/sdb/device/vpd_pg83", 0x83)
	wwn, parsed := parseNAAWWNPage(wwnPage)
	if !valid || serialStatus != identityPresent || string(serial) != qemuDataSerial ||
		wwnStatus != identityPresent || parsed != identityPresent || wwn != "naa."+qemuDataWWN {
		return errors.New("expected disposable QEMU data-disk identity not present")
	}
	return nil
}
