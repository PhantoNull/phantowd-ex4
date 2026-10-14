//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestServerCaptureWorkerFileSlotUsesRealProcReadOnlyDescriptor(t *testing.T) {
	name := filepath.Join(t.TempDir(), "synthetic-object")
	if err := os.WriteFile(name, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	proc, err := os.Open("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	var original unix.Stat_t
	if err := unix.Fstat(int(file.Fd()), &original); err != nil {
		t.Fatal(err)
	}
	slot, flags, err := captureWorkerFileSlotQEMU(context.Background(), proc, original)
	if err != nil || slot != strconv.FormatUint(uint64(file.Fd()), 10) || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		t.Fatal("real original read-only descriptor not selected", slot, flags, err)
	}
	// A second actual readable FD to the same object must make the census
	// ambiguous, not silently adopt whichever slot is enumerated first.
	duplicate, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer duplicate.Close()
	if slot, _, err := captureWorkerFileSlotQEMU(context.Background(), proc, original); err == nil || slot != "" {
		t.Fatal("ambiguous descriptor aliases accepted")
	}
}

func TestServerCaptureWorkerFDFlagsRefuseMalformedDuplicateAndForeignBits(t *testing.T) {
	for _, bad := range []string{"", "flags: 0x1\n", "flags: 02100000 extra\n", "flags: 0\nflags: 0\n", "flags: 00\n", "flags: -1\n", "flags: 0100000000000\n", "flags: 01000\n", strings.Repeat("x", 4097)} {
		if flags, err := captureWorkerFDFlagsQEMU([]byte(bad)); err == nil || flags != 0 {
			t.Fatal("malformed/foreign descriptor flags admitted", bad)
		}
	}
}

func TestServerCaptureWorkerFileSlotRefusesWritePathrefAndCanceledObservations(t *testing.T) {
	name := filepath.Join(t.TempDir(), "synthetic-object")
	if err := os.WriteFile(name, []byte("data"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	proc, err := os.Open("/proc/self")
	if err != nil {
		t.Fatal(err)
	}
	defer proc.Close()
	var original unix.Stat_t
	if unix.Fstat(int(file.Fd()), &original) != nil {
		t.Fatal("stat fixture")
	}
	if slot, _, err := captureWorkerFileSlotQEMU(context.Background(), proc, original); err == nil || slot != "" {
		t.Fatal("writable data descriptor admitted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if slot, _, err := captureWorkerFileSlotQEMU(canceled, proc, original); !errors.Is(err, context.Canceled) || slot != "" {
		t.Fatal("canceled observation published")
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(name, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	pathref := os.NewFile(uintptr(fd), "synthetic-pathref")
	defer pathref.Close()
	if slot, _, err := captureWorkerFileSlotQEMU(context.Background(), proc, original); err == nil || slot != "" {
		t.Fatal("pathref substituted for data descriptor")
	}
}
