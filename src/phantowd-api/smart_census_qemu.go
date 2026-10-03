//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"time"
)

// exerciseQEMUSMARTDiskCensus observes the existing seven disposable SCSI
// fixtures, including the mounted root and deliberately duplicated VPD pair.
// It never opens a block device or admits a SMART command/transport.
func exerciseQEMUSMARTDiskCensus() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sysfs := os.DirFS("/sys")
	before, err := collectSMARTDiskCensus(ctx, sysfs)
	if err != nil {
		return errors.New("QEMU SMART sysfs census failed")
	}
	after, err := collectSMARTDiskCensus(ctx, sysfs)
	if err != nil || !sameSMARTDiskCensus(before, after) || len(before.disks) != 7 {
		return errors.New("QEMU SMART sysfs census is incomplete or changed")
	}
	for index, disk := range before.disks {
		if disk.name != "sd"+string(rune('a'+index)) || disk.generation.DiskSequence == 0 {
			return errors.New("QEMU SMART sysfs leaf roster is incorrect")
		}
		if disk.name == "sda" || disk.name == "sdd" {
			if disk.serialStatus != identityAmbiguous || disk.wwnStatus != identityAmbiguous {
				return errors.New("QEMU SMART census lost ambiguous VPD evidence")
			}
		}
		if disk.name == "sdd" && !disk.readOnly {
			return errors.New("QEMU SMART census lost read-only disk state")
		}
	}
	// Confirm that the selected sda is actually mounted, not just named like
	// the root disk. /proc is consulted only by this QEMU-only assertion.
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return errors.New("QEMU SMART mounted-root evidence is incomplete")
	}
	root := before.disks[0].generation
	for _, mount := range mounts.Mounts {
		if mount.MountPoint == "/" && mount.DeviceMajor == root.Major && mount.DeviceMinor == root.Minor {
			return nil
		}
	}
	return errors.New("QEMU SMART census did not include the actual mounted root")
}
