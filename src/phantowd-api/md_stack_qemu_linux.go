//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const (
	qemuMDMemberASerial  = "PHANTOWD-QEMU-MD-A"
	qemuMDMemberAWNN     = "500f000000000004"
	qemuMDMemberBSerial  = "PHANTOWD-QEMU-MD-B"
	qemuMDMemberBWWN     = "500f000000000005"
	qemuMDFilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"
)

// runQEMUMDStackTest creates a real RAID1 only from the two fixed virtual
// members attached by qemu-smoke.sh. The firmware/kernel QEMU image runs in
// snapshot mode, so mdadm and mkfs writes cannot alter their backing files.
// This is a test fixture, never product discovery or activation logic.
func runQEMUMDStackTest() (result error) {
	if os.Geteuid() != 0 || runtime.GOOS != "linux" || runtime.GOARCH != "arm" ||
		strings.Split(buildARMLevel(), ",")[0] != "5" {
		return errors.New("MD topology fixture requires root inside ARMv5 QEMU")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("MD topology fixture requires Versatile PB")
	}
	sysfs := os.DirFS("/sys")
	if err := verifyQEMUBlockDevice(sysfs, "sde", qemuMDMemberASerial, qemuMDMemberAWNN); err != nil {
		return errors.New("first disposable MD member identity did not match")
	}
	if err := verifyQEMUBlockDevice(sysfs, "sdf", qemuMDMemberBSerial, qemuMDMemberBWWN); err != nil {
		return errors.New("second disposable MD member identity did not match")
	}
	if _, err := os.Stat("/sys/class/block/md0"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed MD test array name is already present")
	}
	if _, err := os.Lstat("/dev/md0"); err == nil || !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed MD test device node is already present")
	}

	initial, err := collectStorage(sysfs)
	if err != nil {
		return errors.New("initial QEMU block inventory is incomplete")
	}
	memberNames := []string{"sde", "sdf"}
	initialMembers := make(map[string]blockObservation, len(memberNames))
	deviceNumbers := make(map[[2]uint32]bool, len(memberNames))
	for _, name := range memberNames {
		member, ok := findWholeBlockObservation(initial.Observations, name)
		if !ok || member.diskSequence == 0 || deviceNumbers[[2]uint32{member.Major, member.Minor}] {
			return errors.New("fixed MD members are not distinct observed whole disks")
		}
		deviceNumbers[[2]uint32{member.Major, member.Minor}] = true
		initialMembers[name] = member
	}
	unrelated, ok := findWholeBlockObservation(initial.Observations, "sdc")
	if !ok {
		return errors.New("fixed unrelated QEMU disk is missing")
	}
	initialMounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return errors.New("initial QEMU mount inventory is unavailable")
	}
	for _, member := range initialMembers {
		mounted, err := observedWholeDiskHasVisibleDependentMount(member, initial.Observations, initialMounts.Mounts)
		if err != nil || mounted {
			return errors.New("disposable MD member is unexpectedly mounted before the fixture")
		}
	}
	unrelatedMounted, err := observedWholeDiskHasVisibleDependentMount(unrelated, initial.Observations, initialMounts.Mounts)
	if err != nil || unrelatedMounted {
		return errors.New("fixed unrelated QEMU disk is unexpectedly mounted before the fixture")
	}

	mountPoint := mountowner.QEMUMDStackFixtureSource
	if _, err := os.Lstat(mountPoint); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixed QEMU MD stack mount point already exists")
	}
	if err := os.Mkdir(mountPoint, 0700); err != nil {
		return errors.New("could not create fixed private MD mount point")
	}
	mounted := false
	cleaned := false
	cleanup := func() error {
		var cleanupErr error
		if mounted {
			if err := unix.Unmount(mountPoint, 0); err != nil {
				cleanupErr = errors.Join(cleanupErr, errors.New("ordinary MD fixture unmount failed"))
			} else {
				mounted = false
			}
		}
		if !mounted {
			if _, err := os.Stat("/sys/class/block/md0"); err == nil {
				if err := runQEMUStorageUtility("mdadm", 10*time.Second, qemuMDStopArguments()...); err != nil {
					cleanupErr = errors.Join(cleanupErr, errors.New("fixed disposable MD array did not stop"))
				} else if err := waitForQEMUBlockNodeRemoval("/sys/class/block/md0", 5*time.Second); err != nil {
					cleanupErr = errors.Join(cleanupErr, errors.New("fixed MD array remains in sysfs after stop"))
				}
			} else if !errors.Is(err, os.ErrNotExist) {
				cleanupErr = errors.Join(cleanupErr, errors.New("fixed MD array state cannot be checked"))
			}
		}
		if err := os.Remove(mountPoint); err != nil && !errors.Is(err, os.ErrNotExist) {
			cleanupErr = errors.Join(cleanupErr, errors.New("private MD mount point cleanup failed"))
		}
		return cleanupErr
	}
	defer func() {
		if !cleaned {
			result = errors.Join(result, cleanup())
		}
	}()

	if err := runQEMUStorageUtility("mdadm", 20*time.Second, qemuMDCreateArguments()...); err != nil {
		return err
	}
	if err := runQEMUStorageUtility("mkfs.ext2", 20*time.Second,
		"-q", "-F", "-U", qemuMDFilesystemUUID, "/dev/md0"); err != nil {
		return err
	}
	arrayInventory, err := collectStorage(sysfs)
	if err != nil {
		return errors.New("created MD sysfs topology is incomplete")
	}
	array, ok := findWholeBlockObservation(arrayInventory.Observations, "md0")
	if !ok || array.diskSequence == 0 || !sameBlockDependencyMembers(array.lowerBlocks, memberNames) {
		return errors.New("created MD node does not expose exactly the two fixed members")
	}
	mdStatus := collectMDArrayInventory(os.DirFS("/proc"), sysfs, time.Now())
	if mdStatus.Status != arrayInventoryAvailable || mdStatus.ArrayCount != 1 || len(mdStatus.Arrays) != 1 {
		return fmt.Errorf("created MD array is not completely observable: %s", formatMDArrayInventoryDiagnostic(mdStatus))
	}
	observedArray := mdStatus.Arrays[0]
	if observedArray.Name != "md0" || observedArray.Level != "raid1" || observedArray.ExpectedDevices != 2 ||
		observedArray.ActiveDevices != 2 || observedArray.DegradedDevices != 0 || observedArray.Health != arrayHealthHealthy ||
		!sameMDMemberNames(observedArray.Members, []mdMemberObservation{{Name: "sde"}, {Name: "sdf"}}) {
		return errors.New("created MD RAID1 member/health observation did not match the fixed fixture")
	}
	if !mdStatus.identityInventoryComplete || observedArray.uuidStatus != identityPresent || !canonicalPrivateMDUUID(observedArray.arrayUUID) {
		return errors.New("MD sysfs inventory did not produce one valid private array UUID")
	}
	arrayMatch, err := matchMDArrayUUID(mdStatus, observedArray.arrayUUID)
	if err != nil || arrayMatch.State != "one-object" || len(arrayMatch.ArrayIndices) != 1 || arrayMatch.ArrayIndices[0] != 0 {
		return errors.New("complete MD UUID inventory did not resolve the fixed array")
	}
	identityGraph, err := collectMDStorageIdentity(sysfs, os.DirFS("/proc"))
	if err != nil || len(identityGraph) != 1 || identityGraph[0].arrayUUID != observedArray.arrayUUID ||
		len(identityGraph[0].memberDisks) != 2 || identityGraph[0].memberDisks[0].serialEvidence == ([32]byte{}) ||
		identityGraph[0].memberDisks[1].wwnEvidence == ([32]byte{}) {
		return errors.New("MD UUID did not correlate with the complete member-disk identity graph")
	}
	encodedArrayStatus, err := json.Marshal(mdStatus)
	if err != nil || strings.Contains(string(encodedArrayStatus), observedArray.arrayUUID) {
		return errors.New("MD UUID escaped the internal read-only identity boundary")
	}

	if err := unix.Mount("/dev/md0", mountPoint, "ext2", unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return errors.New("read-only mount of disposable MD filesystem failed")
	}
	mounted = true
	if err := exerciseQEMUSMARTDiskCensus(); err != nil {
		return err
	}
	smartCensus, err := collectSMARTDiskCensus(context.Background(), sysfs)
	if err != nil {
		return errors.New("SMART census of disposable mounted MD fixture failed")
	}
	smartArray, found := findWholeBlockObservation(smartCensus.snapshot.Observations, "md0")
	if !found || len(smartArray.lowerBlocks) != 2 ||
		!sameMDMemberNames(topologyMembers(smartArray.lowerBlocks), []mdMemberObservation{{Name: "sde"}, {Name: "sdf"}}) {
		return errors.New("SMART census lost the active MD fixture topology")
	}
	fmt.Println("PHANTOWD_SMART_MD_CENSUS_READY complete=true leaves=7 active_md_members=2 mounted_root_included=true device_opened=false command_admitted=false scope=qemu-fixture-only")
	if err := exerciseQEMUSMARTGenerationWitnesses(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SMART_FD_WITNESS_READY active_md_members=2 retained_fd=true caller_close=true mismatch_refused=true review_sticky=true metadata_ioctl=BLKGETDISKSEQ content_read=false smart_command=false scope=qemu-fixture-only")
	if err := exerciseQEMUSMARTCensusWitnessSet(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_SMART_CENSUS_WITNESS_SET_READY leaves=7 complete=true partial_refused=true rollback_no_leak=true caller_close=true review_pins_retained=true reader_failure_sticky=true explicit_release=true content_read=false smart_command=false scope=qemu-fixture-only")
	census, err := collectTrustedMountedExtCensus(context.Background(), sysfs, os.DirFS("/proc"))
	if err != nil || census.coverage.processRootExcluded != 1 || census.coverage.observedRootCount != len(census.identities) {
		return errors.New("private mounted-ext census did not retain complete scoped coverage")
	}
	mdRoots := 0
	for _, identity := range census.identities {
		if identity.anchor == mountPoint {
			if identity.sourceName != "md0" || identity.filesystemUUID != qemuMDFilesystemUUID ||
				len(identity.arrays) != 1 || len(identity.physicalDisks) != 2 || identity.filesystemUUIDConflict {
				return errors.New("private census lost the disposable MD filesystem/member identity")
			}
			mdRoots++
		}
	}
	if mdRoots != 1 {
		return errors.New("complete scoped census omitted the disposable MD filesystem root")
	}
	if _, err := json.Marshal(census); err == nil {
		return errors.New("private mounted-ext census could escape as JSON")
	}
	fmt.Println("PHANTOWD_MOUNTED_EXT_CENSUS_READY namespace_scoped=true roots_from_mountinfo=true rootfs_excluded=true md_members=2 repeated_metadata=true private=true block_opened=false file_data_read=false qualification=false activation=false scope=disposable-qemu-only")
	var mountStat unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, mountPoint, unix.AT_NO_AUTOMOUNT,
		unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &mountStat); err != nil {
		return errors.New("mounted MD fixture identity is unavailable")
	}
	guard, err := mountguard.Open(mountPoint, mountguard.Expected{
		MountID: mountStat.Mnt_id, RootInode: mountStat.Ino, DeviceMajor: mountStat.Dev_major,
		DeviceMinor: mountStat.Dev_minor, FilesystemType: unix.EXT4_SUPER_MAGIC,
		FilesystemUUID: qemuMDFilesystemUUID,
	})
	if err != nil {
		return errors.New("read-only MD fixture mount did not match its expected identity")
	}
	if err := guard.Verify(); err != nil {
		guard.Close()
		return errors.New("read-only MD fixture mount guard verification failed")
	}
	if err := guard.Close(); err != nil {
		return errors.New("read-only MD mount guard close failed")
	}

	mountedInventory, err := collectStorage(sysfs)
	if err != nil {
		return errors.New("mounted MD sysfs topology is incomplete")
	}
	mounts, err := collectMountInventory(os.DirFS("/proc"), time.Now())
	if err != nil {
		return errors.New("mounted MD mount inventory is unavailable")
	}
	mdMountFound := false
	for _, mount := range mounts.Mounts {
		if mount.MountPoint == mountPoint && mount.DeviceMajor == array.Major && mount.DeviceMinor == array.Minor &&
			mount.Filesystem == "ext2" && mount.ReadOnly {
			mdMountFound = true
		}
	}
	if !mdMountFound {
		return errors.New("read-only MD mount was not observed through mountinfo")
	}
	observedMount, err := mountguard.ObserveMounted([]string{mountPoint})
	if err != nil || len(observedMount.Mounts) != 1 || len(observedMount.ConflictingUUIDs) != 0 {
		return errors.New("mounted MD filesystem identity is not completely observable")
	}
	identityStorage, identityArrays, err := collectMDStorageIdentitySnapshot(sysfs, os.DirFS("/proc"))
	if err != nil {
		return errors.New("mounted MD storage identity inputs are incomplete")
	}
	correlated, err := correlateObservedMountedStorageIdentity(identityStorage, identityArrays, observedMount)
	if err != nil || len(correlated) != 1 {
		return errors.New("mounted filesystem did not resolve to its complete MD/member identity")
	}
	identity := correlated[0]
	if identity.anchor != mountPoint || identity.filesystemUUID != qemuMDFilesystemUUID || identity.filesystemUUIDConflict ||
		identity.sourceName != "md0" || identity.sourceMajor != array.Major || identity.sourceMinor != array.Minor ||
		len(identity.arrays) != 1 || identity.arrays[0].arrayName != "md0" ||
		identity.arrays[0].arrayUUID != observedArray.arrayUUID || identity.arrays[0].arrayDiskSeq != array.diskSequence ||
		identity.arrays[0].level != "raid1" ||
		len(identity.arrays[0].memberDisks) != 2 || len(identity.physicalDisks) != 2 {
		return errors.New("mounted MD filesystem, array UUID and member disks did not correlate")
	}
	if err := exerciseQEMUMDToMountedOwnerProvider(mountPoint, identity); err != nil {
		return fmt.Errorf("M3.3 to M3.4 trusted provider bridge: %w", err)
	}
	// This broader smoke has the independent qemu-only ext2 volume required by
	// the two-volume loss fixture. The focused MD v1.0 smoke intentionally has
	// only the two array members, so it exercises the provider bridge alone.
	if err := mountowner.RunQEMUMultiVolumeLeaseLossFixture(); err != nil {
		return fmt.Errorf("M3.5 two-volume lease-loss fixture: %w", err)
	}
	for index, member := range identity.arrays[0].memberDisks {
		if member != identityGraph[0].memberDisks[index] {
			return errors.New("mounted MD identity changed its previously observed member binding")
		}
	}
	seenIdentityDisks := make(map[string]bool, len(identity.physicalDisks))
	for _, disk := range identity.physicalDisks {
		if (disk.diskName != "sde" && disk.diskName != "sdf") || seenIdentityDisks[disk.diskName] || disk.diskSequence == 0 ||
			!((disk.serialStatus == identityPresent && disk.serialEvidence != ([32]byte{})) ||
				(disk.wwnStatus == identityPresent && disk.wwnEvidence != ([32]byte{}))) {
			return errors.New("mounted MD filesystem resolved to an unexpected or unidentified member disk")
		}
		initial, exists := initialMembers[disk.diskName]
		if !exists || initial.Major != disk.major || initial.Minor != disk.minor ||
			initial.diskSequence != disk.diskSequence || initial.SerialStatus != disk.serialStatus ||
			initial.WWNStatus != disk.wwnStatus || initial.serialEvidence != disk.serialEvidence ||
			initial.wwnEvidence != disk.wwnEvidence {
			return errors.New("mounted MD identity changed the member disk generation or VPD evidence")
		}
		seenIdentityDisks[disk.diskName] = true
	}
	if !seenIdentityDisks["sde"] || !seenIdentityDisks["sdf"] {
		return errors.New("mounted MD filesystem did not resolve both fixed member disks")
	}
	for _, name := range memberNames {
		member, ok := findWholeBlockObservation(mountedInventory.Observations, name)
		if !ok || !sameBlockTopologyIdentity(initialMembers[name], member) || member.SizeBytes != initialMembers[name].SizeBytes {
			return errors.New("fixed MD member identity changed during the fixture")
		}
		dependent, err := observedWholeDiskHasVisibleDependentMount(member, mountedInventory.Observations, mounts.Mounts)
		if err != nil || !dependent {
			return fmt.Errorf("read-only MD mount was not attributed to fixed member %s", name)
		}
	}
	unrelatedAfter, ok := findWholeBlockObservation(mountedInventory.Observations, "sdc")
	if !ok || !sameBlockTopologyIdentity(unrelated, unrelatedAfter) {
		return errors.New("fixed unrelated QEMU disk changed during the fixture")
	}
	dependent, err := observedWholeDiskHasVisibleDependentMount(unrelatedAfter, mountedInventory.Observations, mounts.Mounts)
	if err != nil || dependent {
		return errors.New("MD mount was incorrectly attributed to an unrelated QEMU disk")
	}
	fmt.Println("PHANTOWD_MD_FILESYSTEM_IDENTITY_READY filesystem_to_md=true md_uuid_internal=true members=2 readonly_mount=true conflict_free=true scope=disposable-qemu-only")

	if err := cleanup(); err != nil {
		cleaned = true
		return err
	}
	cleaned = true
	finalInventory, err := collectStorage(sysfs)
	if err != nil || findBlockObservationByName(finalInventory.Observations, "md0") {
		return errors.New("stopped MD array remains in the final storage inventory")
	}
	for _, name := range memberNames {
		member, ok := findWholeBlockObservation(finalInventory.Observations, name)
		if !ok || len(member.lowerBlocks) != 0 || !sameBlockTopologyIdentity(initialMembers[name], member) {
			return errors.New("MD cleanup did not restore the two member topology")
		}
	}
	fmt.Println("PHANTOWD_MOUNT_GRAPH_READY backing_members=2 actual_raid1=true readonly_mountinfo=true both_members_attributed=true unrelated_disk_clear=true cleanup=true scope=disposable-qemu-only")
	return nil
}

func exerciseQEMUMDToMountedOwnerProvider(source string, identity mountedStorageIdentity) error {
	if source != mountowner.QEMUMDStackFixtureSource || identity.anchor != source ||
		identity.filesystemUUID != qemuMDFilesystemUUID || identity.filesystemUUIDConflict ||
		identity.sourceName != "md0" || identity.sourceMajor == 0 || identity.arrays == nil || len(identity.arrays) != 1 ||
		identity.arrays[0].arrayName != "md0" || identity.arrays[0].arrayUUID == "" || len(identity.physicalDisks) != 2 {
		return errors.New("M3.3 identity is not the fixed complete QEMU MD/filesystem observation")
	}
	if err := mountowner.WithQEMUMDStackSetEvidence(source, func(evidence mountowner.MountedVolumeSetEvidence) error {
		volumes := evidence.Volumes()
		if !evidence.Complete() || evidence.Generation() == 0 || evidence.Fingerprint() == ([32]byte{}) || len(volumes) != 1 {
			return errors.New("M3.4 Owner returned an incomplete mounted-volume roster")
		}
		volume := volumes[0]
		if volume.VolumeID() != mountowner.QEMUMDStackFixtureVolumeID ||
			volume.FilesystemUUID() != identity.filesystemUUID || volume.MountPath() != shareconfig.VolumeMountRoot+"/"+mountowner.QEMUMDStackFixtureVolumeID ||
			volume.Compatibility() != fileserviceplan.CompatibilityQualified || volume.Generation() == 0 ||
			volume.MountID() == 0 || volume.DeviceMajor() != identity.sourceMajor ||
			volume.DeviceMinor() != identity.sourceMinor || !volume.ReadOnly() {
			return errors.New("M3.4 Owner tuple does not match the M3.3 read-only mounted MD filesystem")
		}
		storage, err := fileserviceplan.StorageFromMountedOwnerSet(evidence)
		if err != nil || !storage.Complete || storage.Generation != evidence.Generation() ||
			storage.OwnerFingerprint != evidence.Fingerprint() || len(storage.Volumes) != 1 ||
			storage.Volumes[0].VolumeID != mountowner.QEMUMDStackFixtureVolumeID ||
			storage.Volumes[0].FilesystemUUID != shareconfig.FilesystemUUID(identity.filesystemUUID) ||
			storage.Volumes[0].MountPath != volume.MountPath() || !storage.Volumes[0].ReadOnly {
			return errors.New("M3.3/M3.4 storage provider did not preserve complete read-only identity evidence")
		}
		if _, err := json.Marshal(evidence); err == nil {
			return errors.New("M3.4 provider evidence unexpectedly became serializable")
		}
		fmt.Println("PHANTOWD_M33_M34_PROVIDER_READY source=complete_md_filesystem_identity owner=live_mount_revalidated roster=complete_for_fixture_only uuid=true device_tuple=true read_only=true planner_snapshot=true activation=false http=false scope=disposable-qemu-only")
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func waitForQEMUBlockNodeRemoval(path string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for {
		_, err := os.Stat(path)
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		if err != nil {
			return errors.New("QEMU block-node removal state could not be checked")
		}
		if !time.Now().Before(deadline) {
			return errors.New("QEMU block node remained present through the removal deadline")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func findWholeBlockObservation(observations []blockObservation, name string) (blockObservation, bool) {
	for _, observation := range observations {
		if observation.Name == name && observation.Kind == "block" {
			return observation, true
		}
	}
	return blockObservation{}, false
}

func findBlockObservationByName(observations []blockObservation, name string) bool {
	for _, observation := range observations {
		if observation.Name == name {
			return true
		}
	}
	return false
}

func sameBlockDependencyMembers(lower []blockTopologyRef, expected []string) bool {
	if len(lower) != len(expected) {
		return false
	}
	found := make(map[string]bool, len(lower))
	for _, reference := range lower {
		if reference.Kind != "block" || reference.DiskSequence == 0 || found[reference.Name] {
			return false
		}
		found[reference.Name] = true
	}
	for _, name := range expected {
		if !found[name] {
			return false
		}
	}
	return true
}

func runQEMUStorageUtility(name string, timeout time.Duration, args ...string) error {
	var executable string
	for _, directory := range []string{"/usr/sbin", "/sbin", "/usr/bin", "/bin"} {
		candidate := directory + "/" + name
		info, err := os.Stat(candidate)
		if err == nil && info.Mode().IsRegular() && info.Mode().Perm()&0111 != 0 {
			executable = candidate
			break
		}
	}
	if executable == "" {
		return fmt.Errorf("fixed QEMU storage utility %s is unavailable", name)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	command := exec.CommandContext(ctx, executable, args...)
	command.Env = []string{"PATH=/usr/sbin:/sbin:/usr/bin:/bin", "HOME=/", "LC_ALL=C", "MDADM_NO_SYSTEMCTL=1"}
	command.Stdout = io.Discard
	var diagnostic qemuUtilityDiagnostic
	command.Stderr = &diagnostic
	if err := command.Run(); err != nil {
		if ctx.Err() != nil {
			return fmt.Errorf("fixed QEMU storage utility %s timed out", name)
		}
		if detail := diagnostic.String(); detail != "" {
			return fmt.Errorf("fixed QEMU storage utility %s failed (%v): %s", name, err, detail)
		}
		return fmt.Errorf("fixed QEMU storage utility %s failed: %w", name, err)
	}
	return nil
}
