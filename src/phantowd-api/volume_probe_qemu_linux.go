//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
	"golang.org/x/sys/unix"
)

// Fixed QEMU harness, not the production broker or arbitrary device opener.
func runProbeFixture(source *os.File) (volumeprobe.Result, error) {
	return volumeprobe.Inspect(context.Background(), source)
}

func probeQEMUUnmountedStorage() error {
	// The dispatcher already requires ARMv5 and exact Versatile PB model.
	if os.Geteuid() != 0 {
		return errors.New("QEMU probe requires fixture root")
	}
	if err := verifyQEMUNFSDevice(os.DirFS("/sys")); err != nil {
		return err
	}
	if err := verifyQEMUBlockDevice(os.DirFS("/sys"), "sdc", qemuCloneSerial, qemuCloneWWN); err != nil {
		return err
	}
	deviceIDs := make(map[string]bool)
	deviceNames := make(map[string]string)
	for _, device := range []string{"sdb", "sdc"} {
		id, err := os.ReadFile("/sys/class/block/" + device + "/dev")
		if err != nil {
			return err
		}
		deviceIDs[strings.TrimSpace(string(id))] = true
		deviceNames[device] = strings.TrimSpace(string(id))
	}
	if len(deviceIDs) != 2 {
		return errors.New("fixture requires distinct virtual devices")
	}
	unmounted := func() error {
		mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
		if err != nil {
			return err
		}
		for _, mount := range mounts.Mounts {
			if deviceIDs[fmt.Sprintf("%d:%d", mount.DeviceMajor, mount.DeviceMinor)] {
				return errors.New("probe fixture disk is already mounted")
			}
		}
		return nil
	}
	if err := unmounted(); err != nil {
		return err
	}
	var sources []*os.File
	defer func() {
		for _, source := range sources {
			source.Close()
		}
	}()
	for _, device := range []string{"sdb", "sdc"} {
		fd, err := unix.Openat2(unix.AT_FDCWD, "/dev/"+device, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC,
			Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if err != nil {
			return err
		}
		source := os.NewFile(uintptr(fd), "qemu-probe-input")
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); err != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK || fmt.Sprintf("%d:%d", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))) != deviceNames[device] {
			source.Close()
			return errors.New("probe descriptor is not an expected virtual block object")
		}
		sources = append(sources, source)
	}
	snapshot, err := volumeprobe.ObserveSet(context.Background(), []*os.File{sources[0], sources[1], sources[0]})
	if err != nil {
		return err
	}
	if len(snapshot.Results()) != 3 {
		return errors.New("incomplete virtual probe snapshot")
	}
	for _, result := range snapshot.Results() {
		if result.Status != "ext-metadata" || result.SourceKind != "block-device" || result.Filesystem != "ext2" || result.FilesystemUUID != qemuNFSVolumeUUID {
			return errors.New("unmounted virtual metadata did not match")
		}
	}
	match, err := snapshot.MatchUUID(qemuNFSVolumeUUID)
	if err != nil || match.State != "conflicting-objects" || len(match.SourceIndices) != 3 {
		return errors.New("unmounted clone conflict missed")
	}
	alias, err := volumeprobe.ObserveSet(context.Background(), []*os.File{sources[0], sources[0]})
	if err != nil {
		return err
	}
	match, err = alias.MatchUUID(qemuNFSVolumeUUID)
	if err != nil || match.State != "one-object" || len(match.SourceIndices) != 2 {
		return errors.New("same block object mistaken for clone")
	}
	match, err = snapshot.MatchUUID("00112233-4455-6677-8899-aabbccddeeff")
	if err != nil || match.State != "not-observed" || len(match.SourceIndices) != 0 {
		return errors.New("unobserved UUID gained a match")
	}
	blank, err := os.CreateTemp("/run", "phantowd-probe-blank-")
	if err != nil {
		return err
	}
	name := blank.Name()
	defer os.Remove(name)
	if err := blank.Truncate(4096); err != nil {
		blank.Close()
		return err
	}
	blank.Close()
	blank, err = os.Open(name)
	if err != nil {
		return err
	}
	result, err := runProbeFixture(blank)
	blank.Close()
	if err != nil || result.Status != "unidentified" || result.SourceKind != "regular-image" || result.Filesystem != "" || result.FilesystemUUID != "" {
		return fmt.Errorf("unidentified regular-image fixture failed: %v", err)
	}
	if err := unmounted(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_VOLUME_PROBE_READY backend=libblkid unmounted_devices=2 readonly_descriptors=true expected_uuid=true unidentified_not_empty=true scope=qemu-fixture-only")
	fmt.Println("PHANTOWD_VOLUME_SET_READY cloned_uuid=true aliases_deduplicated=true unobserved_not_absent=true scope=provided-descriptors-only")
	return nil
}
