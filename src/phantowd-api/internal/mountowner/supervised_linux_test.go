// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"bufio"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

func TestLocalMountParent(t *testing.T) {
	for _, test := range []struct {
		name, propagation string
		accepted          bool
	}{
		{name: "private", accepted: true},
		{name: "shared", propagation: "shared:3 "},
		{name: "slave", propagation: "master:8 "},
		{name: "propagated", propagation: "propagate_from:7 "},
	} {
		t.Run(test.name, func(t *testing.T) {
			line := "42 1 8:1 / / rw " + test.propagation + "- ext4 /dev/sda1 rw"
			err := localMountParent(bufio.NewScanner(strings.NewReader(line)), "42")
			if test.accepted && err != nil || !test.accepted && !errors.Is(err, ErrRejected) {
				t.Fatalf("unexpected propagation result: %v", err)
			}
		})
	}
	if err := localMountParent(bufio.NewScanner(strings.NewReader("420 1 8:1 / / rw - ext4 /dev/sda1 rw")), "42"); !errors.Is(err, ErrRejected) {
		t.Fatalf("missing mount accepted: %v", err)
	}
}

func TestValidateLinuxGrantsRejectsAliasedMembers(t *testing.T) {
	file, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	first := LinuxVolumeGrant{VolumeID: "one", SourcePath: "/run/storage/one", Source: file, Expected: mountguard.Expected{
		MountID: 1, RootInode: 2, DeviceMajor: 8, DeviceMinor: 1, FilesystemType: unix.EXT4_SUPER_MAGIC,
		FilesystemUUID: "11111111-2222-3333-4444-555555555555", RequireWritable: true,
	}}
	second := first
	second.VolumeID = "two"
	second.SourcePath = "/run/storage/two"
	second.Expected.MountID++
	second.Expected.DeviceMinor++
	second.Expected.FilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
	if err := validateLinuxGrants([]LinuxVolumeGrant{first, second}); err != nil {
		t.Fatalf("distinct grants rejected: %v", err)
	}
	for name, alter := range map[string]func(*LinuxVolumeGrant){
		"volume ID": func(grant *LinuxVolumeGrant) { grant.VolumeID = first.VolumeID },
		"mount":     func(grant *LinuxVolumeGrant) { grant.Expected.MountID = first.Expected.MountID },
		"device":    func(grant *LinuxVolumeGrant) { grant.Expected.DeviceMinor = first.Expected.DeviceMinor },
		"UUID":      func(grant *LinuxVolumeGrant) { grant.Expected.FilesystemUUID = first.Expected.FilesystemUUID },
		"cross anchor": func(grant *LinuxVolumeGrant) {
			grant.SourcePath = "/srv/phantowd/volumes/one/nested"
		},
	} {
		t.Run(name, func(t *testing.T) {
			alias := second
			alter(&alias)
			if err := validateLinuxGrants([]LinuxVolumeGrant{first, alias}); !errors.Is(err, ErrInvalid) {
				t.Fatalf("aliased roster passed: %v", err)
			}
		})
	}
}
