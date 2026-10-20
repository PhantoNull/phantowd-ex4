//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"encoding/hex"
	"errors"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

type nfsSourceMountFixtureQEMU struct {
	fixture *qemuMountFixture
	set     *MountedVolumeSet
	cause   error
}

var nfsSourceMountRetainedQEMU *nfsSourceMountFixtureQEMU

// WithQEMUNFSSourceMountedSet exposes only a fixed synthetic 32MiB ext2 disk
// in the explicitly selected ARM guest. ORIGINAL mount/qualification/set refs
// remain retained until VM disposal, including the intentional reviewed-pin
// case. There is no drain/forced cleanup, product inventory or disk import.
func WithQEMUNFSSourceMountedSet(ctx context.Context, inspect func(*MountedVolumeSet) error) (result error) {
	if ctx == nil || ctx.Err() != nil || inspect == nil || nfsSourceMountRetainedQEMU != nil ||
		runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrInvalid
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return ErrInvalid
	}
	command, err := os.ReadFile("/proc/cmdline")
	codeSelectors, sourceSelectors := 0, 0
	for _, word := range strings.Fields(string(command)) {
		switch word {
		case "phantowd_nfs_code_fixture=1":
			codeSelectors++
		case "phantowd_nfs_source_fixture=1":
			sourceSelectors++
		}
	}
	if err != nil || len(command) > 4096 || codeSelectors != 1 || sourceSelectors != 1 {
		return ErrInvalid
	}
	var fs unix.Statfs_t
	for _, path := range []string{"/run", "/srv/phantowd/volumes"} {
		if unix.Statfs(path, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC|unix.ST_RDONLY) != unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC {
			return ErrInvalid
		}
	}
	size, err := os.ReadFile("/sys/block/sdb/size")
	var device, source unix.Stat_t
	if err != nil || strings.TrimSpace(string(size)) != "65536" || unix.Lstat("/dev/sdb", &device) != nil ||
		device.Mode&unix.S_IFMT != unix.S_IFBLK || unix.Stat(qemuFixtureSource, &source) != nil || source.Dev != device.Rdev ||
		unix.Statfs(qemuFixtureSource, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC ||
		fs.Flags&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC|unix.ST_RDONLY) != unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC {
		return ErrInvalid
	}
	// Read ONLY after model, selectors, tmpfs, exact size and mount/device guards.
	fd, err := unix.Open("/dev/sdb", unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "fixed-qemu-nfs-source")
	var superblock [120]byte
	_, readErr := file.ReadAt(superblock[:], 1024)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	if superblock[56] != 0x53 || superblock[57] != 0xef || hex.EncodeToString(superblock[104:120]) != strings.ReplaceAll(qemuFixtureUUID, "-", "") {
		return ErrInvalid
	}
	if err := os.Mkdir(qemuPlannerMountAnchor, 0700); err != nil {
		return err
	}
	f := &nfsSourceMountFixtureQEMU{}
	nfsSourceMountRetainedQEMU = f
	defer func() { f.cause = result }()
	f.fixture, err = newQEMUMountFixtureAtExpected(qemuFixtureSource, qemuPlannerMountAnchor, qemuPlannerVolumeID, "", qemuFixtureUUID, true)
	if err != nil {
		return err
	}
	if err := f.fixture.owner.Qualify(f.fixture.qualification); err != nil {
		return err
	}
	if err := f.fixture.owner.Mount(ctx); err != nil {
		return err
	}
	f.set, err = newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{f.fixture.owner})
	if err != nil {
		return err
	}
	if err := inspect(f.set); err != nil {
		return err
	}
	return f.fixture.owner.Verify()
}
