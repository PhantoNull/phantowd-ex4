//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	qemuMDV10RootSerial    = "PHANTOWD-QEMU-MDV10-ROOT"
	qemuMDV10RootWWN       = "500f000000000101"
	qemuMDV10MemberASerial = "PHANTOWD-QEMU-MDV10-A"
	qemuMDV10MemberAWWN    = "500f000000000102"
	qemuMDV10MemberBSerial = "PHANTOWD-QEMU-MDV10-B"
	qemuMDV10MemberBWWN    = "500f000000000103"
	qemuMDV10DiskSectors   = "65536"
)

// runQEMUMDV10Fixture writes MD 1.0 metadata only to partition 1 on the two
// fixed virtual GPT disks attached by the disposable QEMU harness. The root
// disk is a QEMU snapshot; this is not product discovery or activation.
func runQEMUMDV10Fixture() (result error) {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" || runtime.GOARCH != "arm" ||
		strings.Split(buildARMLevel(), ",")[0] != "5" {
		return errors.New("MD v1.0 fixture requires root inside ARMv5 QEMU")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("MD v1.0 fixture requires Versatile PB")
	}
	if err := verifyQEMUBlockDevice(os.DirFS("/sys"), "sda", qemuMDV10RootSerial, qemuMDV10RootWWN); err != nil {
		return errors.New("MD v1.0 fixture root disk identity did not match")
	}
	if err := verifyQEMUMDV10Member("sdb", qemuMDV10MemberASerial, qemuMDV10MemberAWWN); err != nil {
		return errors.New("first MD v1.0 fixture component did not match its fixed identity and size")
	}
	if err := verifyQEMUMDV10Member("sdc", qemuMDV10MemberBSerial, qemuMDV10MemberBWWN); err != nil {
		return errors.New("second MD v1.0 fixture component did not match its fixed identity and size")
	}
	if _, err := os.Stat("/sys/class/block/sdd"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("unexpected additional SCSI disk in MD v1.0 fixture")
	}
	if err := ensureQEMUMDV10MembersUnmounted(); err != nil {
		return err
	}
	if _, err := os.Stat("/sys/class/block/md0"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed MD v1.0 array name is already present")
	}
	if _, err := os.Lstat("/dev/md0"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed MD v1.0 device node is already present")
	}
	defer func() {
		if _, err := os.Stat("/sys/class/block/md0"); err == nil {
			if stopErr := runQEMUStorageUtility("mdadm", 10*time.Second, qemuMDV10StopArguments()...); stopErr != nil {
				result = errors.Join(result, errors.New("MD v1.0 fixture cleanup could not stop its array"))
			} else if waitErr := waitForQEMUBlockNodeRemoval("/sys/class/block/md0", 5*time.Second); waitErr != nil {
				result = errors.Join(result, errors.New("MD v1.0 fixture array remained after cleanup"))
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			result = errors.Join(result, errors.New("MD v1.0 fixture cleanup could not verify array state"))
		}
	}()
	if err := runQEMUStorageUtility("mdadm", 20*time.Second, qemuMDV10CreateArguments()...); err != nil {
		return err
	}
	if err := verifyQEMUMDV10Array(); err != nil {
		return err
	}
	if err := runQEMUStorageUtility("mdadm", 10*time.Second, qemuMDV10StopArguments()...); err != nil {
		return err
	}
	if err := waitForQEMUBlockNodeRemoval("/sys/class/block/md0", 5*time.Second); err != nil {
		return errors.New("MD v1.0 fixture array did not stop cleanly")
	}
	unix.Sync()
	for _, member := range []struct {
		name, serial, wwn string
	}{{"sdb", qemuMDV10MemberASerial, qemuMDV10MemberAWWN}, {"sdc", qemuMDV10MemberBSerial, qemuMDV10MemberBWWN}} {
		if err := verifyQEMUMDV10Member(member.name, member.serial, member.wwn); err != nil {
			return errors.New("MD v1.0 fixture component identity changed during array creation")
		}
	}
	fmt.Println("PHANTOWD_MD_V10_READY metadata=1.0 raid1=true members=2 gpt=true partition=1 fixed_devices=true array_stopped=true root_snapshot=true scope=disposable-qemu-only")
	return nil
}

func verifyQEMUMDV10Member(name, serial, wwn string) error {
	if err := verifyQEMUBlockDevice(os.DirFS("/sys"), name, serial, wwn); err != nil {
		return err
	}
	diskSize, err := os.ReadFile("/sys/class/block/" + name + "/size")
	if err != nil || strings.TrimSpace(string(diskSize)) != qemuMDV10DiskSectors {
		return errors.New("MD v1.0 fixture disk has unexpected GPT backing size")
	}
	if _, err := os.Stat("/sys/class/block/" + name + "2"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("MD v1.0 fixture disk has an unexpected second partition")
	}
	partition := "/sys/class/block/" + name + "/" + name + "1"
	for path, expected := range map[string]string{
		partition + "/partition": "1",
		partition + "/start":     "2048",
		partition + "/size":      "63455",
	} {
		value, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(value)) != expected {
			return errors.New("MD v1.0 fixture GPT partition geometry differs from its fixed synthetic layout")
		}
	}
	return nil
}

func ensureQEMUMDV10MembersUnmounted() error {
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return errors.New("MD v1.0 fixture mount inventory is unavailable")
	}
	for _, name := range []string{"sdb", "sdb1", "sdc", "sdc1"} {
		device, err := os.ReadFile("/sys/class/block/" + name + "/dev")
		if err != nil {
			return errors.New("MD v1.0 fixture device identity is unavailable")
		}
		parts := strings.Split(strings.TrimSpace(string(device)), ":")
		if len(parts) != 2 {
			return errors.New("MD v1.0 fixture device number is malformed")
		}
		major, majorErr := strconv.ParseUint(parts[0], 10, 32)
		minor, minorErr := strconv.ParseUint(parts[1], 10, 32)
		if majorErr != nil || minorErr != nil {
			return errors.New("MD v1.0 fixture device number is malformed")
		}
		for _, mount := range mounts.Mounts {
			if mount.DeviceMajor == uint32(major) && mount.DeviceMinor == uint32(minor) {
				return errors.New("MD v1.0 fixture component is unexpectedly mounted")
			}
		}
	}
	return nil
}

func verifyQEMUMDV10Array() error {
	for path, expected := range map[string]string{
		"/sys/class/block/md0/md/level":       "raid1",
		"/sys/class/block/md0/md/raid_disks":  "2",
		"/sys/class/block/md0/md/degraded":    "0",
		"/sys/class/block/md0/md/sync_action": "idle",
	} {
		value, err := os.ReadFile(path)
		if err != nil || strings.TrimSpace(string(value)) != expected {
			return fmt.Errorf("MD v1.0 fixture array state differs at %s", path)
		}
	}
	slaves, err := os.ReadDir("/sys/class/block/md0/slaves")
	if err != nil {
		return errors.New("MD v1.0 fixture member topology is unavailable")
	}
	names := make([]string, 0, len(slaves))
	for _, slave := range slaves {
		names = append(names, slave.Name())
	}
	sort.Strings(names)
	if len(names) != 2 || names[0] != "sdb1" || names[1] != "sdc1" {
		return errors.New("MD v1.0 fixture array did not contain only the two fixed members")
	}
	return nil
}
