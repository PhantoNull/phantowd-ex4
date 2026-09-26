//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

func runQEMUMountGuardTest() (result error) {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	workspace, err := os.MkdirTemp("/run", "phantowd-mount-guard-")
	if err != nil {
		return err
	}
	anchor := workspace + "/anchor"
	if err := os.Mkdir(anchor, 0700); err != nil {
		return err
	}
	if err := unix.Mount(smbFixtureAnchor, anchor, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	anchorMounted, nestedMounted, overMounted := true, false, false
	defer func() {
		// Only ordinary unmounts of this fixture's own disposable mounts.
		if overMounted {
			if err := unix.Unmount(anchor, 0); err != nil {
				result = errors.Join(result, err)
			}
		}
		if nestedMounted {
			if err := unix.Unmount(anchor+"/guard-nested", 0); err != nil {
				result = errors.Join(result, err)
			}
		}
		if anchorMounted {
			if err := unix.Unmount(anchor, 0); err != nil {
				result = errors.Join(result, err)
			}
		}
	}()
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, anchor, unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return err
	}
	expected := mountguard.Expected{MountID: st.Mnt_id, RootInode: st.Ino, DeviceMajor: st.Dev_major, DeviceMinor: st.Dev_minor, FilesystemType: unix.EXT4_SUPER_MAGIC, RequireWritable: true}
	root, err := mountguard.Open(anchor, expected)
	if err != nil {
		return fmt.Errorf("qualified test mount rejected: %w", err)
	}
	defer root.Close()
	if other, err := mountguard.Open(workspace, expected); err == nil {
		other.Close()
		return errors.New("ordinary directory accepted as qualified mount")
	}
	for _, name := range []string{"guard-child", "guard-nested"} {
		if err := os.Mkdir(anchor+"/"+name, 0700); err != nil {
			return err
		}
	}
	if err := os.Symlink("/etc", anchor+"/guard-link"); err != nil {
		return err
	}
	if err := os.Symlink(anchor, workspace+"/anchor-link"); err != nil {
		return err
	}
	if other, err := mountguard.Open(workspace+"/anchor-link", expected); err == nil {
		other.Close()
		return errors.New("symlink anchor accepted")
	}
	directory, err := root.OpenDirectory("guard-child")
	if err != nil {
		return err
	}
	if _, err := directory.Read(make([]byte, 1)); err == nil {
		directory.Close()
		return errors.New("metadata descriptor unexpectedly reads contents")
	}
	if err := directory.Close(); err != nil {
		return err
	}
	for _, relative := range []string{"..", "guard-child/../../etc", "/etc", "guard-link", "missing-child", "."} {
		opened, err := root.OpenDirectory(relative)
		if relative == "." {
			if err != nil {
				return err
			}
			opened.Close()
			continue
		}
		if err == nil {
			opened.Close()
			return errors.New("unsafe/missing relative directory accepted")
		}
	}
	if err := unix.Mount(anchor+"/guard-child", anchor+"/guard-nested", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	nestedMounted = true
	if opened, err := root.OpenDirectory("guard-nested"); !errors.Is(err, mountguard.ErrUnsafe) {
		if opened != nil {
			opened.Close()
		}
		return fmt.Errorf("nested same-filesystem bind not rejected: %v", err)
	}
	if err := unix.Unmount(anchor+"/guard-nested", 0); err != nil {
		return err
	}
	nestedMounted = false
	// Remount flags affect only this private bind, not the NFS data mount.
	if err := unix.Mount("", anchor, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		return err
	}
	if err := root.Verify(); !errors.Is(err, mountguard.ErrMismatch) {
		return fmt.Errorf("read-only transition was not rejected: %v", err)
	}
	readOnlyExpected := expected
	readOnlyExpected.RequireWritable = false
	readOnly, err := mountguard.Open(anchor, readOnlyExpected)
	if err != nil {
		return fmt.Errorf("explicit read-only binding failed: %w", err)
	}
	readOnly.Close()
	if err := unix.Mount("", anchor, "", unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
		return err
	}
	// A second bind of the SAME disk/root has a distinct unique mount ID.
	// Device major/minor + inode + filesystem type alone must not accept it.
	if err := unix.Mount(smbFixtureAnchor, anchor, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	overMounted = true
	if err := root.Verify(); !errors.Is(err, mountguard.ErrMismatch) {
		return fmt.Errorf("overmount was not rejected: %v", err)
	}
	if opened, err := root.OpenDirectory("guard-child"); err == nil {
		opened.Close()
		return errors.New("overmounted anchor still usable")
	}
	if err := unix.Unmount(anchor, 0); err != nil {
		return err
	}
	overMounted = false
	if err := root.Verify(); err != nil {
		return err
	}
	if err := root.Close(); err != nil {
		return err
	}
	if err := unix.Unmount(anchor, 0); err != nil {
		return err
	}
	anchorMounted = false
	if other, err := mountguard.Open(anchor, expected); err == nil {
		other.Close()
		return errors.New("missing mount fell back into system filesystem")
	}
	if _, err := os.Lstat(anchor + "/guard-child"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("fixture wrote to unmounted fallback directory")
	}
	fmt.Println("PHANTOWD_MOUNT_GUARD_READY unique_mount_id=true descriptor_pinned=true symlinks_denied=true nested_mount_denied=true overmount_denied=true readonly_change_denied=true fallback_denied=true scope=qemu-fixture-only")
	return nil
}
