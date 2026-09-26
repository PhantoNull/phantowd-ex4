// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountguard

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

func TestIdentityContract(t *testing.T) {
	expected := Expected{MountID: 9000, RootInode: 2, DeviceMajor: 8, DeviceMinor: 16, FilesystemType: unix.EXT4_SUPER_MAGIC, RequireWritable: true}
	base := unix.Statx_t{Mask: unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE, Mode: unix.S_IFDIR | 0755, Mnt_id: 9000, Ino: 2, Dev_major: 8, Dev_minor: 16, Attributes: unix.STATX_ATTR_MOUNT_ROOT, Attributes_mask: unix.STATX_ATTR_MOUNT_ROOT}
	for _, name := range []string{"valid", "old mount ID", "no root support", "ordinary directory", "wrong mount", "wrong inode", "wrong major", "wrong minor", "wrong fs", "readonly", "file"} {
		t.Run(name, func(t *testing.T) {
			st, fs := base, unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC}
			switch name {
			case "old mount ID":
				st.Mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID
			case "no root support":
				st.Attributes_mask = 0
			case "ordinary directory":
				st.Attributes = 0
			case "wrong mount":
				st.Mnt_id++
			case "wrong inode":
				st.Ino++
			case "wrong major":
				st.Dev_major++
			case "wrong minor":
				st.Dev_minor++
			case "wrong fs":
				fs.Type = unix.TMPFS_MAGIC
			case "readonly":
				fs.Flags = unix.ST_RDONLY
			case "file":
				st.Mode = unix.S_IFREG | 0600
			}
			err := match(st, fs, expected, true)
			if (err == nil) != (name == "valid") {
				t.Fatal(name, err)
			}
			if (name == "old mount ID" || name == "no root support") && !errors.Is(err, ErrUnsupported) {
				t.Fatal("unsupported protection must fail closed", err)
			}
		})
	}
	base.Ino = 13
	base.Attributes = 0
	if err := match(base, unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC}, expected, false); err != nil {
		t.Fatal("descendant directory", err)
	}
	expected.RequireWritable = false
	if err := match(base, unix.Statfs_t{Type: unix.EXT4_SUPER_MAGIC, Flags: unix.ST_RDONLY}, expected, false); err != nil {
		t.Fatal("readonly binding", err)
	}
}

func TestPathsAndUnavailableKernel(t *testing.T) {
	for _, p := range []string{"", "/", "relative", "/a/../b", "/a/", "/a\x00b"} {
		if validAbsolute(p) {
			t.Fatal("unsafe anchor", p)
		}
	}
	for _, p := range []string{"", "..", "../x", "/etc", "a//b", "a/./b", "a/../b", "a\\b", "a\x00b"} {
		if validRelative(p) {
			t.Fatal("unsafe descendant", p)
		}
	}
	for _, p := range []string{".", "Books & Comics", "a/b"} {
		if !validRelative(p) {
			t.Fatal(p)
		}
	}
	if _, err := Open(filepath.Join(t.TempDir(), "missing"), Expected{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	for _, err := range []error{unix.ENOSYS, unix.EINVAL, unix.EOPNOTSUPP} {
		if classify(err) != ErrUnsupported {
			t.Fatal(err)
		}
	}
	for _, err := range []error{unix.ELOOP, unix.EXDEV} {
		if classify(err) != ErrUnsafe {
			t.Fatal(err)
		}
	}
}

func TestClosedGuardConcurrency(t *testing.T) {
	r := &Root{closed: true}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 50; j++ {
				if r.Verify() != ErrClosed {
					t.Error("closed Verify")
				}
				if _, err := r.OpenDirectory("."); err != ErrClosed {
					t.Error("closed Open")
				}
				if r.Close() != nil {
					t.Error("repeated Close")
				}
			}
		}()
	}
	wg.Wait()
}

func TestDescriptorResolution(t *testing.T) {
	path := t.TempDir()
	if err := os.Mkdir(filepath.Join(path, "child"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/etc", filepath.Join(path, "escape")); err != nil {
		t.Fatal(err)
	}
	fd, err := openPath(unix.AT_FDCWD, path, false)
	if err != nil {
		t.Fatal("openat2 must be available in supported test environment", err)
	}
	defer unix.Close(fd)
	for _, relative := range []string{".", "child"} {
		child, err := openPath(fd, relative, true)
		if err != nil {
			t.Fatal(err)
		}
		unix.Close(child)
	}
	for _, relative := range []string{"escape", "escape/passwd", "../", "/etc", "missing"} {
		child, err := openPath(fd, relative, true)
		if err == nil {
			unix.Close(child)
			t.Fatal("unsafe resolution succeeded", relative)
		}
	}
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	if err := unix.Fstatfs(fd, &fs); err != nil {
		t.Fatal(err)
	}
	expected := Expected{MountID: st.Mnt_id, RootInode: st.Ino, DeviceMajor: st.Dev_major, DeviceMinor: st.Dev_minor, FilesystemType: uint32(fs.Type), FilesystemUUID: "11111111-2222-3333-4444-555555555555"}
	if err := matchFD(fd, expected, false); st.Mask&unix.STATX_MNT_ID_UNIQUE != 0 {
		if err != nil {
			t.Fatal(err)
		}
	} else if !errors.Is(err, ErrUnsupported) {
		t.Fatal("older kernel silently accepted", err)
	}
	if candidate, err := Open(path, expected); err == nil {
		candidate.Close()
		t.Fatal("ordinary temporary directory accepted as a mount root")
	}
	if err := matchFD(-1, expected, false); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid fd", err)
	}
}

func TestZeroValueDoesNotOwnDescriptorZero(t *testing.T) {
	var root Root
	if root.Verify() != ErrClosed {
		t.Fatal("zero value is not closed")
	}
	if _, err := root.OpenDirectory("."); err != ErrClosed {
		t.Fatal(err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}
