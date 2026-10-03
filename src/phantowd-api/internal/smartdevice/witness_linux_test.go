// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartdevice

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
	"golang.org/x/sys/unix"
)

func TestGenerationObservationFailsClosed(t *testing.T) {
	g := volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 42}
	s := unix.Stat_t{Mode: unix.S_IFBLK, Rdev: unix.Mkdev(8, 16)}
	if !validObservation(s, unix.O_RDONLY|unix.O_NONBLOCK, unix.FD_CLOEXEC, g, 42) {
		t.Fatal("valid observation refused")
	}
	for _, mutate := range []func(*unix.Stat_t, *int, *int, *volumeprobe.BlockDeviceGeneration, *uint64){
		func(s *unix.Stat_t, _, _ *int, _ *volumeprobe.BlockDeviceGeneration, _ *uint64) {
			s.Mode = unix.S_IFREG
		},
		func(s *unix.Stat_t, _, _ *int, _ *volumeprobe.BlockDeviceGeneration, _ *uint64) {
			s.Rdev = unix.Mkdev(8, 32)
		},
		func(s *unix.Stat_t, _, _ *int, _ *volumeprobe.BlockDeviceGeneration, _ *uint64) {
			s.Rdev = unix.Mkdev(9, 16)
		},
		func(_ *unix.Stat_t, f, _ *int, _ *volumeprobe.BlockDeviceGeneration, _ *uint64) { *f = unix.O_RDWR },
		func(_ *unix.Stat_t, f, _ *int, _ *volumeprobe.BlockDeviceGeneration, _ *uint64) { *f = unix.O_WRONLY },
		func(_ *unix.Stat_t, f, _ *int, _ *volumeprobe.BlockDeviceGeneration, _ *uint64) { *f = unix.O_PATH },
		func(_ *unix.Stat_t, _, f *int, _ *volumeprobe.BlockDeviceGeneration, _ *uint64) { *f = 0 },
		func(_ *unix.Stat_t, _, _ *int, g *volumeprobe.BlockDeviceGeneration, _ *uint64) {
			*g = volumeprobe.BlockDeviceGeneration{}
		},
		func(_ *unix.Stat_t, _, _ *int, _ *volumeprobe.BlockDeviceGeneration, n *uint64) { *n = 0 },
		func(_ *unix.Stat_t, _, _ *int, _ *volumeprobe.BlockDeviceGeneration, n *uint64) { *n = 43 },
	} {
		stat, flags, cloexec, expected, sequence := s, unix.O_RDONLY, unix.FD_CLOEXEC, g, uint64(42)
		mutate(&stat, &flags, &cloexec, &expected, &sequence)
		if validObservation(stat, flags, cloexec, expected, sequence) {
			t.Fatal("unsafe observation accepted")
		}
	}
}

func TestRetainRejectsNonBlockAndLeavesCallerOpen(t *testing.T) {
	g := volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 0, DiskSequence: 1}
	name := filepath.Join(t.TempDir(), "regular")
	if err := os.WriteFile(name, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []int{os.O_RDONLY, os.O_RDWR, os.O_WRONLY, unix.O_PATH} {
		file, err := os.OpenFile(name, mode, 0)
		if err != nil {
			t.Fatal(err)
		}
		if w, err := Retain(context.Background(), file, g); w != nil || !errors.Is(err, ErrUnsafe) {
			t.Fatal(w, err)
		}
		if _, err := file.Stat(); err != nil {
			t.Fatal("caller closed", err)
		}
		file.Close()
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	file.Close()
	if w, err := Retain(context.Background(), file, g); w != nil || !errors.Is(err, ErrUnsafe) {
		t.Fatal(w, err)
	}
	if w, err := Retain(nil, file, g); w != nil || !errors.Is(err, ErrUnsafe) {
		t.Fatal(w, err)
	}
	if w, err := Retain(context.Background(), nil, g); w != nil || !errors.Is(err, ErrUnsafe) {
		t.Fatal(w, err)
	}
	data, err := os.ReadFile(name)
	if err != nil || string(data) != "untouched" {
		t.Fatal("contents changed", err)
	}
}

func TestWitnessLifecycleRefusesForgedCopiedBusyAndReviewedHandles(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	w := &Witness{gate: make(chan struct{}, 1), file: file, expected: volumeprobe.BlockDeviceGeneration{Major: 8, DiskSequence: 1}}
	w.self = w
	// This fixture is intentionally NOT a block device: failed Check must retain
	// the descriptor in review, not release it or become usable after restoration.
	copy := *w
	if err := copy.Check(context.Background()); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	if err := copy.Close(context.Background()); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	w.gate <- struct{}{}
	if err := w.Check(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if err := w.Close(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	<-w.gate
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := w.Check(ctx); !errors.Is(err, context.Canceled) || w.review {
		t.Fatal(err)
	}
	if err := w.Close(ctx); !errors.Is(err, context.Canceled) || w.closed {
		t.Fatal(err)
	}
	if err := w.Check(context.Background()); !errors.Is(err, ErrUnsafe) || !w.review {
		t.Fatal(err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("review released the pin", err)
	}
	if err := w.Check(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	if _, err := json.Marshal(w); !errors.Is(err, ErrPrivate) {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte("{}"), w); !errors.Is(err, ErrPrivate) {
		t.Fatal(err)
	}
	if err := w.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Stat(); err == nil {
		t.Fatal("duplicate was not closed")
	}
	if err := w.Check(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if err := w.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	var missing *Witness
	if err := missing.Check(context.Background()); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
}

func TestRetainRefusalPreservesOffsetFlagsAndDoesNotLeakDuplicates(t *testing.T) {
	name := filepath.Join(t.TempDir(), "retained-refusal")
	if err := os.WriteFile(name, []byte("untouched"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	if _, err := file.Seek(3, 0); err != nil {
		t.Fatal(err)
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	if err != nil {
		t.Fatal(err)
	}
	descriptorFlags, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0)
	if err != nil {
		t.Fatal(err)
	}
	countReferences := func() int {
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		count := 0
		for _, entry := range entries {
			target, err := os.Readlink("/proc/self/fd/" + entry.Name())
			if err == nil && target == name {
				count++
			}
		}
		return count
	}
	if got := countReferences(); got != 1 {
		t.Fatal("unexpected source references", got)
	}
	g := volumeprobe.BlockDeviceGeneration{Major: 8, DiskSequence: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w, err := Retain(ctx, file, g); w != nil || !errors.Is(err, context.Canceled) {
		t.Fatal(w, err)
	}
	if w, err := Retain(context.Background(), file, volumeprobe.BlockDeviceGeneration{}); w != nil || !errors.Is(err, ErrUnsafe) {
		t.Fatal(w, err)
	}
	for i := 0; i < 128; i++ {
		if w, err := Retain(context.Background(), file, g); w != nil || !errors.Is(err, ErrUnsafe) {
			t.Fatal(w, err)
		}
	}
	if got := countReferences(); got != 1 {
		t.Fatal("duplicate leaked after refusal", got)
	}
	if got, err := file.Seek(0, 1); err != nil || got != 3 {
		t.Fatal("caller offset changed", got, err)
	}
	if got, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0); err != nil || got != flags {
		t.Fatal("caller status flags changed", got, err)
	}
	if got, err := unix.FcntlInt(file.Fd(), unix.F_GETFD, 0); err != nil || got != descriptorFlags {
		t.Fatal("caller descriptor flags changed", got, err)
	}
}
