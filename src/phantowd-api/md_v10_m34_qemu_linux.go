//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

// runQEMUMDV10M34Fixture consumes only the already-created GPT/MD v1.0 test
// members. It first requires a fresh complete read-only M3.3 broker assessment,
// then reassembles those exact virtual partitions read-only, mounts their
// synthetic ext2 filesystem read-only, and sends the observed mount tuple
// through the QEMU-only M3.4 Owner/planner bridge. No firmware or real disk
// path can invoke this fixture.
func runQEMUMDV10M34Fixture() (result error) {
	// Ask the non-root broker through its ordinary API-UID client path. The
	// root QEMU fixture driver must not bypass the broker and read block nodes.
	if err := runQEMUMDV10BrokerClientAsAPIUser(); err != nil {
		return errors.New("complete read-only MD v1.0 provider evidence is required before the mounted-owner fixture")
	}

	var volumeRoot unix.Statfs_t
	if unix.Statfs(shareconfig.VolumeMountRoot, &volumeRoot) != nil || uint64(volumeRoot.Type) != uint64(unix.TMPFS_MAGIC) {
		return errors.New("M3.4 fixture mount anchors must be backed by the dedicated QEMU tmpfs")
	}

	mountPoint := mountowner.QEMUMDStackFixtureSource
	if _, err := os.Lstat(mountPoint); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed MD v1.0 source mountpoint already exists")
	}
	if err := os.Mkdir(mountPoint, 0700); err != nil {
		return errors.New("could not create the fixed MD v1.0 source mountpoint")
	}
	mounted := false
	arrayActive := false
	uncertain := false
	defer func() {
		if uncertain {
			result = errors.Join(result, errors.New("MD v1.0 M3.4 fixture state is uncertain; leave it for disposable-guest reboot cleanup"))
			return
		}
		if mounted {
			if err := unix.Unmount(mountPoint, 0); err != nil {
				uncertain = true
				result = errors.Join(result, errors.New("read-only MD v1.0 fixture unmount failed; no retry attempted"))
				return
			}
			mounted = false
		}
		if arrayActive {
			if err := verifyQEMUMDV10Array(); err != nil {
				uncertain = true
				result = errors.Join(result, errors.New("MD v1.0 fixture array identity changed; refusing to stop an unexpected array"))
				return
			}
			if err := runQEMUStorageUtility("mdadm", 10*time.Second, qemuMDV10StopArguments()...); err != nil {
				uncertain = true
				result = errors.Join(result, errors.New("MD v1.0 fixture stop result is uncertain; no retry attempted"))
				return
			}
			if err := waitForQEMUBlockNodeRemoval("/sys/class/block/md0", 5*time.Second); err != nil {
				uncertain = true
				result = errors.Join(result, errors.New("MD v1.0 fixture array remained after its single stop request"))
				return
			}
			arrayActive = false
		}
		if err := os.Remove(mountPoint); err != nil {
			result = errors.Join(result, errors.New("fixed MD v1.0 mountpoint cleanup failed"))
		}
	}()

	if err := runQEMUStorageUtility("mdadm", 20*time.Second, qemuMDV10AssembleReadonlyArguments()...); err != nil {
		uncertain = true
		return errors.New("read-only assembly of the two fixed synthetic GPT partitions failed")
	}
	arrayActive = true
	if err := verifyQEMUMDV10Array(); err != nil {
		return errors.New("reassembled MD v1.0 array does not match its two fixed fixture members")
	}
	device, err := unix.Open("/dev/md0", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errors.New("read-only MD v1.0 device could not be opened for a mode check")
	}
	readOnly, ioctlErr := unix.IoctlGetInt(device, unix.BLKROGET)
	closeErr := unix.Close(device)
	if ioctlErr != nil || closeErr != nil || readOnly != 1 {
		return errors.New("reassembled MD v1.0 block device is not verified read-only")
	}
	if err := unix.Mount("/dev/md0", mountPoint, "ext2", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		uncertain = true
		return errors.New("read-only mount of the synthetic MD v1.0 ext2 filesystem failed")
	}
	mounted = true

	observedMount, err := mountguard.ObserveMounted([]string{mountPoint})
	if err != nil || len(observedMount.Mounts) != 1 || len(observedMount.ConflictingUUIDs) != 0 ||
		observedMount.Mounts[0].FilesystemUUID != qemuMDFilesystemUUID ||
		observedMount.Mounts[0].DeviceMajor == 0 {
		return errors.New("mounted MD v1.0 ext2 filesystem identity is incomplete or unexpected")
	}
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return errors.New("MD v1.0 fixture mount inventory could not be revalidated")
	}
	readOnlyMountFound := false
	for _, mount := range mounts.Mounts {
		if mount.MountPoint == mountPoint && mount.DeviceMajor == observedMount.Mounts[0].DeviceMajor &&
			mount.DeviceMinor == observedMount.Mounts[0].DeviceMinor && mount.Filesystem == "ext2" && mount.ReadOnly {
			readOnlyMountFound = true
		}
	}
	if !readOnlyMountFound {
		return errors.New("mountinfo did not confirm the exact ext2 filesystem is read-only")
	}

	storage, arrays, err := collectMDStorageIdentitySnapshot(os.DirFS("/sys"), os.DirFS("/proc"))
	if err != nil {
		return errors.New("reassembled MD v1.0 array identity could not be reconciled")
	}
	identities, err := correlateObservedMountedStorageIdentity(storage, arrays, observedMount)
	if err != nil || len(identities) != 1 {
		return errors.New("mounted filesystem did not resolve to exactly one complete MD/member identity")
	}
	identity := identities[0]
	if identity.sourceName != "md0" || identity.sourceMajor != observedMount.Mounts[0].DeviceMajor ||
		identity.sourceMinor != observedMount.Mounts[0].DeviceMinor || identity.filesystemUUIDConflict ||
		identity.filesystemUUID != qemuMDFilesystemUUID || len(identity.arrays) != 1 ||
		identity.arrays[0].level != "raid1" || len(identity.physicalDisks) != 2 ||
		!sameMDMemberDiskNames(identity.physicalDisks, []string{"sdb", "sdc"}) {
		return errors.New("mounted filesystem did not retain the expected MD v1.0 array/member identity")
	}
	if err := exerciseQEMUMDToMountedOwnerProvider(mountPoint, identity); err != nil {
		uncertain = true
		return fmt.Errorf("M3.3 MD v1.0 to M3.4 Owner/planner bridge: %w", err)
	}
	fmt.Println("PHANTOWD_MD_V10_M34_OWNER_READY metadata=1.0 raid1=true candidates=2 active_roles=complete filesystem_uuid=true member_topology=true assembly_readonly=true mount_readonly=true owner_live_revalidated=true planner_snapshot=true activation=false http=false scope=disposable-qemu-only")
	return nil
}

func sameMDMemberDiskNames(disks []mountedPhysicalDiskIdentity, expected []string) bool {
	if len(disks) != len(expected) {
		return false
	}
	seen := make(map[string]bool, len(disks))
	for _, disk := range disks {
		if disk.diskName == "" || seen[disk.diskName] {
			return false
		}
		seen[disk.diskName] = true
	}
	for _, name := range expected {
		if !seen[name] {
			return false
		}
	}
	return true
}
