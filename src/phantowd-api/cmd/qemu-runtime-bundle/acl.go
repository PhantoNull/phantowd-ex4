//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"runtime"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// A separate root-only, disposable permission regression. The caller has
// already checked the exact QEMU board and fixed argument. Mount changes stay
// on this locked thread's private namespace; nothing touches the Samba tree,
// guest disk fixtures, parent namespace or product launcher.
func inspectACLFixture() error {
	runtime.LockOSThread()
	// Do not unlock a thread with a different mount namespace for Go to reuse.
	if err := unix.Unshare(unix.CLONE_NEWNS); err != nil {
		return err
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	const base = "/run/phantowd-bundle-permissions"
	if err := os.Mkdir(base, 0700); err != nil {
		return err
	}
	const payload = "disposable code bytes\n"
	plan, err := runtimebundle.NewPlan([]runtimebundle.File{{Path: "lib/code", SHA256: sha256.Sum256([]byte(payload)), Size: int64(len(payload)), Mode: 0555}}, nil)
	if err != nil {
		return err
	}
	for _, test := range []struct{ name, object, attribute string }{
		{"baseline", "", ""},
		{"root-access", "", "system.posix_acl_access"},
		{"root-default", "", "system.posix_acl_default"},
		{"directory-access", "/lib", "system.posix_acl_access"},
		{"directory-default", "/lib", "system.posix_acl_default"},
		{"file-access", "/lib/code", "system.posix_acl_access"},
	} {
		name := base + "/" + test.name
		if err := os.Mkdir(name, 0755); err != nil {
			return err
		}
		if err := os.Mkdir(name+"/lib", 0755); err != nil {
			return err
		}
		if err := os.WriteFile(name+"/lib/code", []byte(payload), 0555); err != nil {
			return err
		}
		if test.attribute != "" {
			owner := uint16(7)
			if test.object == "/lib/code" {
				owner = 5
			}
			// Linux POSIX ACL xattr version 2, five sorted entries. UID1803
			// has no access despite unchanged 0755/0555 mode and file hash.
			acl := make([]byte, 4+5*8)
			binary.LittleEndian.PutUint32(acl, 2)
			for i, entry := range []struct {
				tag, permission uint16
				id              uint32
			}{
				{1, owner, ^uint32(0)}, {2, 0, 1803},
				{4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 5, ^uint32(0)},
			} {
				offset := 4 + i*8
				binary.LittleEndian.PutUint16(acl[offset:], entry.tag)
				binary.LittleEndian.PutUint16(acl[offset+2:], entry.permission)
				binary.LittleEndian.PutUint32(acl[offset+4:], entry.id)
			}
			if err := unix.Setxattr(name+test.object, test.attribute, acl, unix.XATTR_CREATE); err != nil {
				return err
			}
			got := make([]byte, len(acl)+1)
			count, err := unix.Getxattr(name+test.object, test.attribute, got)
			if err != nil || count != len(acl) || !bytes.Equal(got[:count], acl) {
				return errors.New("actual kernel ACL evidence missing")
			}
			info, err := os.Stat(name + test.object)
			if err != nil || info.Mode().Perm() != os.FileMode(owner<<6|5<<3|5) {
				return errors.New("ACL changed expected Unix mode")
			}
		}
		if err := unix.Mount(name, name, "", unix.MS_BIND, ""); err != nil {
			return err
		}
		if err := unix.Mount("", name, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
			return err
		}
		root, err := stageRoot(name)
		if err != nil {
			return err
		}
		observation, inspectErr := plan.Inspect(context.Background(), root)
		closeErr := root.Close()
		unmountErr := unix.Unmount(name, 0)
		if closeErr != nil || unmountErr != nil {
			return errors.New("disposable inspection cleanup")
		}
		if test.attribute == "" {
			if inspectErr != nil || observation != (runtimebundle.Observation{Files: 1, Bytes: int64(len(payload))}) {
				return errors.Join(errors.New("ACL-free positive control"), inspectErr)
			}
		} else if !errors.Is(inspectErr, runtimebundle.ErrMismatch) || observation != (runtimebundle.Observation{}) {
			fmt.Println("PHANTOWD_RUNTIME_BUNDLE_ACL_ACCEPTED case=" + test.name)
			return errors.New("undeclared code ACL accepted")
		}
	}
	fmt.Println("PHANTOWD_SAMBA_ROOT_CODE_ACL_READY baseline=true root=true directories=true files=true refusals=5 scope=qemu-only")
	return nil
}
