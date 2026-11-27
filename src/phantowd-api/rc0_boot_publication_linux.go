// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

// Publication pins the launcher's already admitted state. It never searches
// for media or mounts a block device.
func publishRC0BootGrant(ctx context.Context) error {
	state, err := takeStartupFile(3, unix.S_IFDIR)
	if err != nil {
		return err
	}
	defer state.Close()
	plan, err := readRC0BootGrant(4)
	if err != nil {
		return err
	}
	policy, proofInfo, err := readRC0PolicyGrant(5)
	if err != nil || !plan.matchesPolicy(policy) {
		return errRC0Review
	}
	root, err := lockRC0StateRoot(state)
	if err != nil {
		return err
	}
	defer root.Close()
	if !plan.matchesState(root) || !rc0BootServiceAbsent() || ctx.Err() != nil {
		return errRC0Review
	}
	policyDir, err := openRC0Role(root, "nas-policy", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	independent := independentRC0PolicyProof(policyDir, proofInfo)
	if err := policyDir.Close(); err != nil || !independent {
		return errRC0Review
	}
	tls, err := openRC0TLSIdentity(root)
	if err != nil {
		return err
	}
	matches := plan.matchesTLS(tls)
	if err := tls.Close(); err != nil || !matches {
		return errRC0Review
	}
	return stageRC0BootGrant(ctx, root, plan, policy)
}

// The caller holds the boot lifecycle and original state-root locks.
func stageRC0BootGrant(ctx context.Context, root *os.File, plan rc0BootPlan, policy []byte) error {
	if !rc0BootServiceAbsent() || ctx.Err() != nil {
		return errRC0Review
	}
	run, err := os.Open("/run")
	if err != nil {
		return err
	}
	defer run.Close()
	if !rc0AbsentRole(run, rc0BootGrantName) || !rc0AbsentRole(run, rc0BootStagingName) {
		return errRC0Review
	}
	// A partial staging directory is deliberately retained for review. The
	// private tmpfs contains all publication changes, including the mount clone.
	if err := unix.Mkdirat(int(run.Fd()), rc0BootStagingName, 0700); err != nil {
		return err
	}
	stage, err := openRC0BootDirectory(run, rc0BootStagingName)
	if err != nil {
		return err
	}
	defer stage.Close()
	if err := unix.Mkdirat(int(stage.Fd()), "state", 0700); err != nil {
		return err
	}
	observed, err := attachRC0BootClone(root, stage)
	if err != nil || observed.Mnt_id == plan.StateMountID || observed.Ino != plan.StateRootInode {
		return errRC0Review
	}
	plan.StateMountID = observed.Mnt_id
	data, err := json.Marshal(plan)
	if err != nil {
		return err
	}
	if len(data) > rc0BootMaxBytes {
		return errRC0Review
	}
	if err := writeRC0BootRole(stage, "boot.json", data); err != nil {
		return err
	}
	if err := writeRC0BootRole(stage, "policy.json", policy); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fd := int(run.Fd())
	return unix.Renameat2(fd, rc0BootStagingName, fd, rc0BootGrantName, unix.RENAME_NOREPLACE)
}

func attachRC0BootClone(source, stage *os.File) (unix.Statx_t, error) {
	target, err := openRC0Role(stage, "state", unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return unix.Statx_t{}, err
	}
	defer target.Close()
	fd, err := unix.OpenTree(int(source.Fd()), "", unix.AT_EMPTY_PATH|unix.OPEN_TREE_CLONE|unix.OPEN_TREE_CLOEXEC)
	if err != nil {
		return unix.Statx_t{}, err
	}
	defer unix.Close(fd)
	attr := unix.MountAttr{Attr_set: unix.MOUNT_ATTR_NOSUID | unix.MOUNT_ATTR_NODEV | unix.MOUNT_ATTR_NOEXEC}
	if err := unix.MountSetattr(fd, "", unix.AT_EMPTY_PATH, &attr); err != nil {
		return unix.Statx_t{}, err
	}
	if err := unix.MoveMount(fd, "", int(target.Fd()), "",
		unix.MOVE_MOUNT_F_EMPTY_PATH|unix.MOVE_MOUNT_T_EMPTY_PATH); err != nil {
		return unix.Statx_t{}, err
	}
	attached, err := openRC0BootState(stage)
	if err != nil {
		return unix.Statx_t{}, err
	}
	defer attached.Close()
	observed, err := inspectRC0BootClone(attached)
	var original unix.Stat_t
	if err != nil || unix.Fstat(int(source.Fd()), &original) != nil ||
		unix.Mkdev(observed.Dev_major, observed.Dev_minor) != uint64(original.Dev) {
		return unix.Statx_t{}, errRC0Review
	}
	return observed, nil
}

func inspectRC0BootClone(file *os.File) (unix.Statx_t, error) {
	const mask = unix.STATX_MNT_ID_UNIQUE | unix.STATX_INO
	const flags = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	fd := int(file.Fd())
	var observed unix.Statx_t
	var fs unix.Statfs_t
	if unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &observed) != nil ||
		observed.Mask&mask != mask || observed.Mnt_id == 0 || observed.Attributes&unix.STATX_ATTR_MOUNT_ROOT == 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&flags != flags {
		return unix.Statx_t{}, errRC0Review
	}
	return observed, nil
}

func writeRC0BootRole(stage *os.File, name string, data []byte) error {
	fd, err := unix.Openat(int(stage.Fd()), name,
		unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), name)
	_, err = file.Write(data)
	return errors.Join(err, file.Close())
}

func rc0BootServiceAbsent() bool {
	_, err := os.Lstat(rc0BootControlDir)
	return errors.Is(err, os.ErrNotExist)
}

func withdrawRC0BootGrant() error {
	run, err := os.Open("/run")
	if err != nil {
		return err
	}
	defer run.Close()
	if !rc0BootServiceAbsent() || !rc0AbsentRole(run, rc0BootStagingName) {
		return errRC0Review
	}
	grant, err := openRC0BootDirectory(run, rc0BootGrantName)
	if err != nil {
		return err
	}
	defer grant.Close()
	if !fixedRC0BootInventory(grant) {
		return errRC0Review
	}
	planFile, err := openRC0PrivateFile(grant, "boot.json", rc0BootMaxBytes)
	if err != nil {
		return err
	}
	data, _, readErr := readPrivateStartupFile(planFile, 0, rc0BootMaxBytes)
	if err := errors.Join(readErr, planFile.Close()); err != nil {
		return err
	}
	plan, err := decodeRC0BootPlan(data)
	if err != nil {
		return err
	}
	state, err := openRC0BootState(grant)
	if err != nil {
		return err
	}
	defer state.Close()
	root, err := lockRC0StateRoot(state)
	if err != nil {
		return err
	}
	defer root.Close()
	observed, err := inspectRC0BootClone(root)
	if err != nil || observed.Mnt_id != plan.StateMountID || observed.Ino != plan.StateRootInode {
		return errRC0Review
	}

	fd := int(run.Fd())
	if err := unix.Renameat2(fd, rc0BootGrantName, fd, rc0BootStagingName, unix.RENAME_NOREPLACE); err != nil {
		return err
	}
	// The clone's descriptors would keep the mount busy. The published path
	// has already been removed and the lifecycle lock still excludes init.
	if err := errors.Join(root.Close(), state.Close()); err != nil {
		return err
	}
	if err := unix.Unmount("/run/"+rc0BootStagingName+"/state", 0); err != nil {
		return err
	}
	dir := int(grant.Fd())
	for _, name := range []string{"boot.json", "policy.json"} {
		if err := unix.Unlinkat(dir, name, 0); err != nil {
			return err
		}
	}
	if err := unix.Unlinkat(dir, "state", unix.AT_REMOVEDIR); err != nil {
		return err
	}
	return unix.Unlinkat(fd, rc0BootStagingName, unix.AT_REMOVEDIR)
}

func fixedRC0BootInventory(grant *os.File) bool {
	entries, err := grant.ReadDir(4)
	if (err != nil && !errors.Is(err, io.EOF)) || len(entries) != 3 {
		return false
	}
	for _, entry := range entries {
		switch entry.Name() {
		case "boot.json", "policy.json":
			if !entry.Type().IsRegular() {
				return false
			}
		case "state":
			if !entry.IsDir() {
				return false
			}
		default:
			return false
		}
	}
	return true
}
