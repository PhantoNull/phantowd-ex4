//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"golang.org/x/sys/unix"
)

type volumeProbeResult struct {
	SchemaVersion          int    `json:"schema_version"`
	Status                 string `json:"status"`
	SourceKind             string `json:"source_kind"`
	Filesystem             string `json:"filesystem"`
	FilesystemUUID         string `json:"filesystem_uuid"`
	MountPerformed         bool   `json:"mount_performed"`
	CompatibilityQualified bool   `json:"compatibility_qualified"`
	ActivationAllowed      bool   `json:"activation_allowed"`
}

type probeOutput struct{ bytes.Buffer }

func (out *probeOutput) Write(data []byte) (int, error) {
	if out.Len()+len(data) > 1024 {
		return 0, errors.New("excessive probe output")
	}
	return out.Buffer.Write(data)
}

// Fixed QEMU harness, not the production broker or arbitrary device opener.
func runProbeFixture(source *os.File) (volumeProbeResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/libexec/phantowd-volume-probe")
	cmd.Env = []string{"LC_ALL=C", "PATH=/usr/bin:/bin", "BLKID_DEBUG=0"}
	cmd.Stdin = source
	cmd.WaitDelay = time.Second
	var output, diagnostic probeOutput
	cmd.Stdout, cmd.Stderr = &output, &diagnostic
	if err := cmd.Run(); err != nil || diagnostic.Len() != 0 {
		return volumeProbeResult{}, errors.New("descriptor probe process failed")
	}
	var result volumeProbeResult
	fields := map[string]bool{"schema_version": true, "status": true, "source_kind": true,
		"filesystem": true, "filesystem_uuid": true, "mount_performed": true,
		"compatibility_qualified": true, "activation_allowed": true}
	if err := configjson.Decode(bytes.NewReader(output.Bytes()), &result, 1024, 2, fields); err != nil {
		return volumeProbeResult{}, errors.New("invalid probe response")
	}
	if result.SchemaVersion != 1 || result.MountPerformed || result.CompatibilityQualified || result.ActivationAllowed {
		return volumeProbeResult{}, errors.New("probe exceeded observation boundary")
	}
	return result, nil
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
		result, err := runProbeFixture(source)
		source.Close()
		if err != nil || result.Status != "ext-metadata" || result.SourceKind != "block-device" || result.Filesystem != "ext2" || result.FilesystemUUID != qemuNFSVolumeUUID {
			return fmt.Errorf("unmounted virtual metadata did not match: %v", err)
		}
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
	return nil
}
