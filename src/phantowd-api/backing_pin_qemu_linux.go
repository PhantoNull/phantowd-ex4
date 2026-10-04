//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/backingpin"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"golang.org/x/sys/unix"
)

func exerciseQEMUBackingPin(workspace, qualifiedAnchor string, root *mountguard.Root, expected mountguard.Expected) (result error) {
	if err := backingpin.RunQEMUFixture(root, qualifiedAnchor); err != nil {
		return err
	}
	if err := backingpin.RunQEMUWritableFixture(root, qualifiedAnchor); err != nil {
		return err
	}
	// Separate private bind: flag transitions must not revoke other guard tests.
	anchor := workspace + "/backing-anchor"
	if err := os.Mkdir(anchor, 0700); err != nil {
		return err
	}
	if err := unix.Mount(qualifiedAnchor, anchor, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(anchor, 0)) }()
	var st unix.Statx_t
	if err := unix.Statx(unix.AT_FDCWD, anchor, unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return err
	}
	expected.MountID, expected.RootInode = st.Mnt_id, st.Ino
	private, err := mountguard.Open(anchor, expected)
	if err != nil {
		return err
	}
	defer func(r *mountguard.Root) { result = errors.Join(result, r.Close()) }(private)
	dir, err := os.MkdirTemp(anchor, "backing-flags-")
	if err != nil {
		return err
	}
	relative := dir[len(anchor)+1:]
	// Clean using the still-writable source if a failure leaves the private bind RO.
	unsafeCleanup := false
	defer func() {
		if !unsafeCleanup {
			result = errors.Join(result, os.RemoveAll(qualifiedAnchor+"/"+relative))
		}
	}()
	file := dir + "/file"
	if err := os.WriteFile(file, make([]byte, 4096), 0600); err != nil {
		return err
	}
	if err := os.Mkdir(dir+"/nested", 0700); err != nil {
		return err
	}
	if err := unix.Mount(dir, dir+"/nested", "", unix.MS_BIND, ""); err != nil {
		return err
	}
	other, _, openErr := backingpin.Open(private, relative+"/nested/file", 4096)
	if other != nil {
		other.Close()
	}
	unmountErr := unix.Unmount(dir+"/nested", 0)
	if unmountErr != nil {
		unsafeCleanup = true // Never recurse through an uncertain remaining bind.
		return unmountErr
	}
	if !errors.Is(openErr, backingpin.ErrUnavailable) {
		return errors.New("nested bind backing accepted")
	}
	p, _, err := backingpin.Open(private, relative+"/file", 4096)
	if err != nil {
		return err
	}
	defer func(pin *backingpin.Pin) { result = errors.Join(result, pin.Close()) }(p)
	// Same-filesystem bind over the leaf is also a different mount identity.
	if err := unix.Mount(file, file, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	_, driftErr := p.Verify()
	if err := unix.Unmount(file, 0); err != nil {
		unsafeCleanup = true
		return err
	}
	if !errors.Is(driftErr, backingpin.ErrReview) {
		return errors.New("leaf bind overmount accepted")
	}
	if _, err := p.Verify(); !errors.Is(err, backingpin.ErrReview) {
		return errors.New("leaf mount restoration revived pin")
	}
	if err := p.Close(); err != nil {
		return err
	}
	p, _, err = backingpin.Open(private, relative+"/file", 4096)
	if err != nil {
		return err
	}
	defer func(pin *backingpin.Pin) { result = errors.Join(result, pin.Close()) }(p)
	if err := unix.Mount("", anchor, "", unix.MS_REMOUNT|unix.MS_BIND|unix.MS_RDONLY, ""); err != nil {
		return err
	}
	_, driftErr = p.Verify()
	if err := unix.Mount("", anchor, "", unix.MS_REMOUNT|unix.MS_BIND, ""); err != nil {
		return err
	}
	if !errors.Is(driftErr, backingpin.ErrReview) {
		return errors.New("read-only transition accepted")
	}
	if _, err := p.Verify(); !errors.Is(err, backingpin.ErrReview) {
		return errors.New("read-only restoration revived pin")
	}
	if err := p.Close(); err != nil {
		return err
	}
	private, err = mountguard.Open(anchor, expected)
	if err != nil {
		return err
	}
	defer func(r *mountguard.Root) { result = errors.Join(result, r.Close()) }(private)
	p, _, err = backingpin.Open(private, relative+"/file", 4096)
	if err != nil {
		return err
	}
	defer func(pin *backingpin.Pin) { result = errors.Join(result, pin.Close()) }(p)
	if err := private.Close(); err != nil {
		return err
	}
	if _, err := p.Verify(); !errors.Is(err, backingpin.ErrReview) {
		return errors.New("closed borrowed root accepted")
	}
	if err := p.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_BACKING_PIN_READY metadata_only=true actual_ext_root=true exact_size=true unsafe_objects_denied=true nested_mount_denied=true leaf_overmount_denied=true retained_review=true restore_denied=true readonly_change_denied=true root_loss_denied=true serialized_close=true writable_authority=false target=false scope=disposable-qemu-only")
	return nil
}
