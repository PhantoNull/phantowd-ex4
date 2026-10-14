//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

const revisionMediaRootQEMU = "/run/phantowd-revisionstore-media"

func requireRevisionMediaQEMU(t *testing.T) {
	t.Helper()
	if runtime.GOARCH != "arm" {
		t.Skip("dedicated synthetic ARM guest only")
	}
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		t.Fatal("fixture command line unavailable", err)
	}
	markers := 0
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_revisionstore_media_fixture=1" {
			markers++
		}
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || len(model) > 128 || strings.TrimRight(string(model), "\x00") != "ARM Versatile PB" || markers != 1 || os.Geteuid() != 0 || os.Getenv("TMPDIR") != revisionMediaRootQEMU {
		t.Fatal("not the fixed disposable media fixture", err)
	}
	var fs unix.Statfs_t
	var root, device unix.Stat_t
	const restrictions = unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if unix.Statfs(revisionMediaRootQEMU, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || fs.Flags&(restrictions|unix.ST_RDONLY) != restrictions || fs.Bsize <= 0 || fs.Blocks*uint64(fs.Bsize) > 32<<20 || fs.Blocks*uint64(fs.Bsize) < 8<<20 ||
		unix.Lstat(revisionMediaRootQEMU, &root) != nil || root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Uid != 0 || root.Gid != 0 ||
		unix.Stat("/dev/sdb", &device) != nil || device.Mode&unix.S_IFMT != unix.S_IFBLK || root.Dev != device.Rdev {
		t.Fatal("fixed bounded synthetic ext4 mount unavailable")
	}
}

func TestRevisionStoreMediaReadOnlyRetainsConfirmedPolicyAndReview(t *testing.T) {
	requireRevisionMediaQEMU(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, nasKillPolicy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := OpenOwnedWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	const restrictions = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC
	if err := unix.Mount("", revisionMediaRootQEMU, "", unix.MS_REMOUNT|unix.MS_RDONLY|restrictions, ""); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := unix.Mount("", revisionMediaRootQEMU, "", unix.MS_REMOUNT|restrictions, ""); err != nil {
			t.Error("restore synthetic mount", err)
		}
	}()
	var fs unix.Statfs_t
	if err := unix.Statfs(revisionMediaRootQEMU, &fs); err != nil || fs.Flags&unix.ST_RDONLY == 0 {
		t.Fatal("read-only state not established", err)
	}
	ctx := context.Background()
	if err := o.Commit(ctx, 1, nasKillPolicy(2)); !errors.Is(err, ErrReview) {
		t.Fatal("read-only publication was not quarantined", err)
	}
	if _, err := o.Snapshot(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("uncertain owner returned healthy policy", err)
	}
	if other, err := OpenWithCodec(dir, nasKillCodec()); !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("review released exclusive lock", err)
	}
	if err := unix.Mount("", revisionMediaRootQEMU, "", unix.MS_REMOUNT|restrictions, ""); err != nil {
		t.Fatal(err)
	}
	if err := o.Commit(ctx, 1, nasKillPolicy(2)); !errors.Is(err, ErrReview) {
		t.Fatal("mount restoration permitted retry", err)
	}
	if _, err := o.Acquire(ctx, 1); !errors.Is(err, ErrReview) {
		t.Fatal("mount restoration admitted a claim", err)
	}
	// No consumer was started: this is an explicit fixture close and read-only
	// reconciliation, not an automatic product recovery/reopen procedure.
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal("confirmed state unavailable", err)
	}
	defer s.Close()
	if got, err := s.Load(); err != nil || !reflect.DeepEqual(got, nasKillPolicy(1)) {
		t.Fatal("confirmed three-protocol policy changed", got, err)
	}
}

func TestRevisionStoreMediaFullFilesystemRetainsConfirmedPolicyAndReview(t *testing.T) {
	requireRevisionMediaQEMU(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, nasKillPolicy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := OpenOwnedWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	// A sibling on the fixed 32-MiB guest mount: do not inject an error into
	// the store or modify its owned directory merely to simulate fullness.
	name := revisionMediaRootQEMU + "/fixture-full.bin"
	f, err := os.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	defer os.Remove(name)
	buffer := make([]byte, 4<<10)
	full := false
	for written := 0; written < 32<<20; {
		n, err := f.Write(buffer)
		written += n
		if errors.Is(err, unix.ENOSPC) {
			full = true
			break
		}
		if err != nil || n != len(buffer) {
			t.Fatal("unexpected synthetic fill result", n, err)
		}
	}
	if !full {
		t.Fatal("bounded synthetic write never reached real ENOSPC")
	}
	if err := f.Sync(); err != nil && !errors.Is(err, unix.ENOSPC) {
		t.Fatal("synthetic fill sync", err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	var fs unix.Statfs_t
	// Extending the existing filler can fail while a fresh file can still
	// allocate data. A bounded tail fill consumes those remaining blocks;
	// ENOSPC on the large file alone must NOT qualify the publication test.
	var tails []string
	defer func() {
		for _, name := range tails {
			_ = os.Remove(name)
		}
	}()
	for i := 0; i < 16; i++ {
		if err := unix.Statfs(revisionMediaRootQEMU, &fs); err != nil {
			t.Fatal(err)
		}
		if fs.Bavail == 0 {
			break
		}
		tailName := fmt.Sprintf("%s/fixture-tail-%02d.bin", revisionMediaRootQEMU, i)
		tail, err := os.OpenFile(tailName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			t.Fatal("bounded tail creation", err)
		}
		tails = append(tails, tailName)
		n, writeErr := tail.Write([]byte{1})
		syncErr := tail.Sync()
		closeErr := tail.Close()
		if n != 1 || writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal("bounded tail allocation", n, writeErr, syncErr, closeErr)
		}
	}
	if err := unix.Statfs(revisionMediaRootQEMU, &fs); err != nil || fs.Bavail != 0 {
		t.Fatal("full filesystem not established", fs.Bavail, err)
	}
	ctx := context.Background()
	if err := o.Commit(ctx, 1, nasKillPolicy(2)); !errors.Is(err, ErrReview) {
		t.Fatal("full-media publication not quarantined", err)
	}
	if _, err := o.Snapshot(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("full-media owner returned healthy policy", err)
	}
	if other, err := OpenWithCodec(dir, nasKillCodec()); !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("full-media review released lock", err)
	}
	pendingName := filepath.Join(dir, nasKillCodec().PendingName)
	pending, pendingErr := os.ReadFile(pendingName)
	if pendingErr != nil && !errors.Is(pendingErr, os.ErrNotExist) {
		t.Fatal(pendingErr)
	}
	if err := os.Remove(name); err != nil {
		t.Fatal("free synthetic space", err)
	}
	if err := unix.Statfs(revisionMediaRootQEMU, &fs); err != nil || fs.Bavail == 0 {
		t.Fatal("synthetic space not freed", err)
	}
	if err := o.Commit(ctx, 1, nasKillPolicy(2)); !errors.Is(err, ErrReview) {
		t.Fatal("freed space permitted retry", err)
	}
	if _, err := o.Acquire(ctx, 1); !errors.Is(err, ErrReview) {
		t.Fatal("freed space admitted a claim", err)
	}
	// No active consumer: explicit fixture close and read-only reconciliation.
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	s, err = OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal("confirmed policy unavailable", err)
	}
	defer s.Close()
	if got, err := s.Load(); err != nil || !reflect.DeepEqual(got, nasKillPolicy(1)) {
		t.Fatal("full filesystem changed confirmed policy", got, err)
	}
	after, afterErr := os.ReadFile(pendingName)
	if !reflect.DeepEqual(after, pending) || (pendingErr == nil) != (afterErr == nil) || (afterErr != nil && !errors.Is(afterErr, os.ErrNotExist)) {
		t.Fatal("reconciliation altered pending evidence", pendingErr, afterErr)
	}
}
