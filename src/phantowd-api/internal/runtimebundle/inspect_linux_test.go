//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func TestInspectionRefusesWritableRootAndInvalidDescriptors(t *testing.T) {
	p, err := NewPlan([]File{exampleFile("lib/file")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Inspect(context.Background(), nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "temporary-writable-root")
	defer root.Close()
	if got, err := p.Inspect(context.Background(), root); err == nil || got != (Observation{}) {
		t.Fatal("writable root accepted", got, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Inspect(ctx, root); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := p.Inspect(nil, root); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := (*Plan)(nil).Inspect(context.Background(), root); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := (&Plan{}).Inspect(context.Background(), root); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestOpenBeneathSupportsPathOnlyAndReadableDirectories(t *testing.T) {
	root, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	for _, flags := range []int{unix.O_PATH | unix.O_DIRECTORY, unix.O_RDONLY | unix.O_DIRECTORY} {
		fd, err := openBeneath(root, ".", flags)
		if err != nil {
			t.Fatalf("bounded directory open refused flags %x: %v", flags, err)
		}
		_ = unix.Close(fd)
	}
}

func TestOpenBeneathRefusesSymlinkTraversalWithoutBlockingOnFIFO(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(dir+"/actual", 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("actual", dir+"/alias"); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(dir+"/fifo", 0600); err != nil {
		t.Fatal(err)
	}
	root, err := unix.Open(dir, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(root)
	for _, flags := range []int{unix.O_PATH | unix.O_DIRECTORY, unix.O_RDONLY | unix.O_DIRECTORY} {
		if fd, err := openBeneath(root, "alias", flags); err == nil {
			_ = unix.Close(fd)
			t.Fatal("symlink traversal accepted")
		}
	}
	fd, err := openBeneath(root, "fifo", unix.O_RDONLY)
	if err != nil {
		t.Fatal("nonblocking descriptor open failed", err)
	}
	defer unix.Close(fd)
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_NONBLOCK == 0 {
		t.Fatal("data open lost nonblocking protection", err)
	}
}

func TestCodeFilesystemRosterExcludesRemoteAndUnqualifiedBackends(t *testing.T) {
	for _, fsType := range []int64{unix.TMPFS_MAGIC, unix.SQUASHFS_MAGIC, unix.EXT4_SUPER_MAGIC} {
		if !localCodeFilesystem(fsType) {
			t.Fatal("fixed local code filesystem refused", fsType)
		}
	}
	for _, fsType := range []int64{0, unix.NFS_SUPER_MAGIC, unix.FUSE_SUPER_MAGIC, unix.PROC_SUPER_MAGIC} {
		if localCodeFilesystem(fsType) {
			t.Fatal("unqualified code backing accepted", fsType)
		}
	}
}
