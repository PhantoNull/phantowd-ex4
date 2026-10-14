//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"golang.org/x/sys/unix"
)

func TestPendingHealthyLocalIdentityOnlyIgnoresAccessTime(t *testing.T) {
	initial := unix.Stat_t{Dev: 1, Ino: 2, Mode: unix.S_IFREG | 0600, Uid: 2001, Gid: 2001, Nlink: 1, Size: 4096}
	accessed := initial
	accessed.Atim.Sec++
	if !samePendingObjectQEMU(initial, accessed) {
		t.Fatal("permitted read atime refused")
	}
	for _, mutate := range []func(*unix.Stat_t){
		func(s *unix.Stat_t) { s.Dev++ }, func(s *unix.Stat_t) { s.Ino++ },
		func(s *unix.Stat_t) { s.Mode++ }, func(s *unix.Stat_t) { s.Uid++ },
		func(s *unix.Stat_t) { s.Gid++ }, func(s *unix.Stat_t) { s.Nlink++ },
		func(s *unix.Stat_t) { s.Size++ }, func(s *unix.Stat_t) { s.Mtim.Sec++ },
		func(s *unix.Stat_t) { s.Ctim.Sec++ },
	} {
		changed := initial
		mutate(&changed)
		if samePendingObjectQEMU(initial, changed) {
			t.Fatal("local object replacement/drift accepted")
		}
	}
}

func TestPendingHealthyBytesBoundedAndOriginalOffsetUnchanged(t *testing.T) {
	if verifyPendingBytesQEMU(nil) == nil {
		t.Fatal("missing object accepted")
	}
	for index, data := range [][]byte{bytes.Repeat([]byte{0x3c}, 4096), bytes.Repeat([]byte{0x3c}, 4095), bytes.Repeat([]byte{0x3c}, 4097), bytes.Repeat([]byte{0xa5}, 4096)} {
		name := filepath.Join(t.TempDir(), "synthetic-object")
		if err := os.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		if (verifyPendingBytesQEMU(file) == nil) != (index == 0) {
			t.Fatal("exact original payload/length not enforced")
		}
		if offset, err := file.Seek(0, 1); err != nil || offset != 0 {
			t.Fatal("original file offset consumed")
		}
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestPendingHealthyHostGuardAndCancellationDoNotConsumeAdmission(t *testing.T) {
	var plan *Plan
	if plan.ProbeNativePendingClientQEMU(nil, nil, nil, nil, fileserviceplan.SambaEnrollmentLookup{}, [2]*os.File{}) == nil {
		t.Fatal("nil context accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(plan.ProbeNativePendingClientQEMU(ctx, nil, nil, nil, fileserviceplan.SambaEnrollmentLookup{}, [2]*os.File{}), context.Canceled) {
		t.Fatal("cancellation lost")
	}
	if plan.ProbeNativePendingClientQEMU(context.Background(), nil, nil, nil, fileserviceplan.SambaEnrollmentLookup{}, [2]*os.File{}) == nil || pendingHealthyAttemptedQEMU.Load() || pendingHealthyRetainedQEMU != nil {
		t.Fatal("host guard consumed or retained fixture admission")
	}
}
