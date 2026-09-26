//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/sharestore"
	"golang.org/x/sys/unix"
)

const qemuStateAnchor = "/run/phantowd-state-volume"

// Fixed virtual disk only, inside a dedicated two-boot QEMU harness. This is
// NOT a product state-location decision, mount broker or deployment operation.
func runQEMUStateTest(phase string) (result error) {
	if phase != "seed" && phase != "verify" {
		return errors.New("unknown QEMU state phase")
	}
	// Reuse the exact ARMv5 / Versatile PB / synthetic VPD checks.
	if os.Geteuid() != 0 {
		return errors.New("QEMU state fixture requires guest root")
	}
	if err := runQEMUNFSTest("verify-disk"); err != nil {
		return err
	}
	device, err := os.ReadFile("/sys/class/block/sdb/dev")
	if err != nil {
		return err
	}
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return err
	}
	for _, mount := range mounts.Mounts {
		if fmt.Sprintf("%d:%d", mount.DeviceMajor, mount.DeviceMinor) == strings.TrimSpace(string(device)) {
			return errors.New("QEMU state disk already mounted")
		}
	}
	fd, err := unix.Openat2(unix.AT_FDCWD, "/dev/sdb", &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	source := os.NewFile(uintptr(fd), "qemu-state-disk")
	defer source.Close()
	var st unix.Stat_t
	if unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFBLK ||
		fmt.Sprintf("%d:%d", unix.Major(uint64(st.Rdev)), unix.Minor(uint64(st.Rdev))) != strings.TrimSpace(string(device)) {
		return errors.New("unexpected QEMU state device")
	}
	probe, err := runProbeFixture(source)
	if err != nil || probe.Status != "ext-metadata" || probe.Filesystem != "ext2" || probe.FilesystemUUID != qemuNFSVolumeUUID {
		return errors.New("unexpected QEMU state filesystem")
	}
	if err := os.Mkdir(qemuStateAnchor, 0700); err != nil {
		return err
	}
	// The source FD stays pinned; only the fixed, host-generated QEMU medium
	// may be mounted writable. No device node or state directory is formatted.
	if err := unix.Mount(fmt.Sprintf("/proc/self/fd/%d", fd), qemuStateAnchor, "ext4", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(qemuStateAnchor, 0)) }()
	var sx unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, qemuStateAnchor, unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &sx); err != nil {
		return err
	}
	guard, err := mountguard.Open(qemuStateAnchor, mountguard.Expected{
		MountID: sx.Mnt_id, RootInode: sx.Ino, DeviceMajor: unix.Major(uint64(st.Rdev)), DeviceMinor: unix.Minor(uint64(st.Rdev)),
		FilesystemType: unix.EXT4_SUPER_MAGIC, FilesystemUUID: qemuNFSVolumeUUID, RequireWritable: true,
	})
	if err != nil {
		return err
	}
	if err := guard.Close(); err != nil {
		return err
	}
	return exerciseQEMUStatePersistence(qemuStateAnchor, phase)
}

func qemuPersistentPolicy(revision uint64) shareconfig.Config {
	return shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: revision,
		Volumes: []shareconfig.Volume{{ID: "fixture-volume", FilesystemUUID: qemuNFSVolumeUUID}},
		Users:   []shareconfig.User{{ID: "fixture-reader", Name: "qreader"}},
		Shares: []shareconfig.Share{{ID: "fixture-share", Name: "Books", VolumeID: "fixture-volume", RelativePath: "books",
			Grants: []shareconfig.Grant{{UserID: "fixture-reader", Access: "ro"}}}}}
}

// Software scenarios are separate from the guarded guest mount for host tests.
// This harness owns all files here. No recovery code directly writes JSON.
func exerciseQEMUStatePersistence(root, phase string) error {
	if phase != "seed" && phase != "verify" {
		return errors.New("unknown state scenario")
	}
	good, corrupt := root+"/good", root+"/corrupt"
	pending, err := json.Marshal(qemuPersistentPolicy(3))
	if err != nil {
		return err
	}
	if phase == "seed" {
		for _, dir := range []string{good, corrupt} {
			if err := os.Mkdir(dir, 0700); err != nil {
				return err
			}
		}
		s, err := sharestore.Open(good)
		if err != nil {
			return err
		}
		defer s.Close()
		for revision := uint64(1); revision <= 2; revision++ {
			if err := s.Commit(revision-1, qemuPersistentPolicy(revision)); err != nil {
				return err
			}
		}
		if err := s.Close(); err != nil {
			return err
		}
		for _, dir := range []string{good, corrupt} {
			if err := writeQEMUStateFixture(dir+"/.shares.pending", pending); err != nil {
				return err
			}
		}
		if err := writeQEMUStateFixture(corrupt+"/shares.json", []byte("{truncated")); err != nil {
			return err
		}
		for _, dir := range []string{good, corrupt, root} {
			if err := syncQEMUStateDirectory(dir); err != nil {
				return err
			}
		}
		return nil
	}
	s, err := sharestore.Open(good)
	if err != nil {
		return err
	}
	defer s.Close()
	loaded, err := s.Load()
	if err != nil || !reflect.DeepEqual(loaded, qemuPersistentPolicy(2)) {
		return errors.New("committed policy was lost or pending state promoted")
	}
	if err := s.Commit(1, qemuPersistentPolicy(2)); !errors.Is(err, sharestore.ErrConflict) {
		return errors.New("stale writer accepted after boot")
	}
	if err := s.Commit(2, qemuPersistentPolicy(3)); err != nil {
		return err
	}
	if _, err := os.Lstat(good + "/.shares.pending"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("pending state was not replaced by committed policy")
	}
	if err := s.Close(); err != nil {
		return err
	}
	s, err = sharestore.Open(good)
	if err != nil {
		return err
	}
	defer s.Close()
	loaded, err = s.Load()
	if err != nil || !reflect.DeepEqual(loaded, qemuPersistentPolicy(3)) {
		return errors.New("post-boot commit did not reopen")
	}
	if err := s.Close(); err != nil {
		return err
	}
	if err := exerciseQEMUSharePolicyHTTP(good, qemuPersistentPolicy(3)); err != nil {
		return err
	}
	bad, err := sharestore.Open(corrupt)
	if bad != nil {
		bad.Close()
	}
	if !errors.Is(err, sharestore.ErrInvalid) {
		return errors.New("corrupt state was not refused")
	}
	for name, expected := range map[string][]byte{"shares.json": []byte("{truncated"), ".shares.pending": pending} {
		data, err := os.ReadFile(corrupt + "/" + name)
		if err != nil || !bytes.Equal(data, expected) {
			return errors.New("corrupt evidence changed during refusal")
		}
	}
	return nil
}

func writeQEMUStateFixture(path string, data []byte) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, writeErr := f.Write(data)
	syncErr := f.Sync()
	return errors.Join(writeErr, syncErr, f.Close())
}

func syncQEMUStateDirectory(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	return errors.Join(f.Sync(), f.Close())
}
