// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"encoding/binary"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestRetainedSambaStateKeepsOriginalDirectoriesAndAllowsMutableContents(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private state fixture requires root")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"private", "lock", "state", "cache", "pid", "rpc"} {
		if err := os.Mkdir(directory+"/"+name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	caller := os.NewFile(uintptr(fd), "state-caller")
	defer caller.Close()
	state, err := retainSambaState(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	defer state.release()
	if err := caller.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(directory+"/private/passdb.tdb", []byte("mutable fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := state.revalidate(context.Background()); err != nil {
		t.Fatal("normal state write treated as immutable drift:", err)
	}
	if err := os.Rename(directory+"/private", directory+"/previous-private"); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(directory+"/private", 0700); err != nil {
		t.Fatal(err)
	}
	if err := state.revalidate(context.Background()); err == nil {
		t.Fatal("identical-mode replacement of private state accepted")
	}
}

func TestRetainedSambaStateRefusesIncompleteOrUnprotectedDirectories(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private state fixture requires root")
	}
	for _, fault := range []string{"missing", "symlink", "public-mode", "special-mode", "access-acl", "default-acl"} {
		t.Run(fault, func(t *testing.T) {
			directory := t.TempDir()
			if err := os.Chmod(directory, 0700); err != nil {
				t.Fatal(err)
			}
			for _, name := range sambaStateDirectories[1:] {
				if err := os.Mkdir(directory+"/"+name, 0700); err != nil {
					t.Fatal(err)
				}
			}
			path := directory + "/private"
			switch fault {
			case "missing", "symlink":
				if err := os.Remove(path); err != nil {
					t.Fatal(err)
				}
				if fault == "symlink" {
					if err := os.Symlink("cache", path); err != nil {
						t.Fatal(err)
					}
				}
			case "public-mode", "special-mode":
				mode := uint32(0755)
				if fault == "special-mode" {
					mode = 01700
				}
				if err := unix.Chmod(path, mode); err != nil {
					t.Fatal(err)
				}
			case "access-acl", "default-acl":
				// Kernel-validated ACL bytes, not a fake xattr response. The mask
				// is zero: this leaves mode0700 and exercises the xattr boundary.
				acl := make([]byte, 4+5*8)
				binary.LittleEndian.PutUint32(acl, 2)
				for index, entry := range []struct {
					tag, permission uint16
					id              uint32
				}{{1, 7, ^uint32(0)}, {2, 7, 1000}, {4, 0, ^uint32(0)}, {16, 0, ^uint32(0)}, {32, 0, ^uint32(0)}} {
					offset := 4 + index*8
					binary.LittleEndian.PutUint16(acl[offset:], entry.tag)
					binary.LittleEndian.PutUint16(acl[offset+2:], entry.permission)
					binary.LittleEndian.PutUint32(acl[offset+4:], entry.id)
				}
				attribute := "system.posix_acl_access"
				if fault == "default-acl" {
					attribute = "system.posix_acl_default"
				}
				if err := unix.Setxattr(path, attribute, acl, 0); err != nil {
					t.Fatal("kernel ACL fixture unavailable:", err)
				}
			}
			fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			caller := os.NewFile(uintptr(fd), "state-refusal-caller")
			defer caller.Close()
			state, err := retainSambaState(context.Background(), caller)
			if state != nil {
				_ = state.release()
			}
			if state != nil || err == nil {
				t.Fatal("unprotected state admitted", fault, err)
			}
			if _, err := caller.Stat(); err != nil {
				t.Fatal("refused admission closed caller", err)
			}
		})
	}
}

func TestRetainedSambaStateCancellationAndRelease(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private state fixture requires root")
	}
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range sambaStateDirectories[1:] {
		if err := os.Mkdir(directory+"/"+name, 0700); err != nil {
			t.Fatal(err)
		}
	}
	fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	caller := os.NewFile(uintptr(fd), "state-lifecycle-caller")
	defer caller.Close()
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if state, err := retainSambaState(canceled, caller); state != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled admission accepted", err)
	}
	state, err := retainSambaState(context.Background(), caller)
	if err != nil {
		t.Fatal(err)
	}
	defer state.release()
	if err := state.revalidate(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation reported success", err)
	}
	if err := state.revalidate(context.Background()); err != nil {
		t.Fatal("canceled observation altered healthy state", err)
	}
	if err := state.release(); err != nil {
		t.Fatal(err)
	}
	if err := state.release(); err != nil {
		t.Fatal("repeat release", err)
	}
	if err := state.revalidate(context.Background()); err == nil {
		t.Fatal("released state still available")
	}
	if _, err := caller.Stat(); err != nil {
		t.Fatal("release closed caller", err)
	}
}
