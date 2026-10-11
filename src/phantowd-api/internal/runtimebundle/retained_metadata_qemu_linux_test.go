//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

// A real read-only code-inspection fixture, not executable/process authority.
// Mount writes are confined to a fresh RAM filesystem in the explicitly
// guarded VersatilePB guest. Native hosts and EX4 hardware must skip it.
func retainedMetadataRAMFixtureQEMU(t *testing.T) *retainedCode {
	t.Helper()
	if !retainedMetadataGuestAllowedQEMU() {
		t.Skip("requires the explicitly guarded disposable ARMv5 code-owner guest")
	}
	var temporaryFS unix.Statfs_t
	if os.Getenv("TMPDIR") != "/run" || unix.Statfs("/run", &temporaryFS) != nil || temporaryFS.Type != unix.TMPFS_MAGIC {
		t.Fatal("metadata fixtures require the prepared /run RAM temporary root")
	}
	directory := t.TempDir()
	if err := unix.Mount("tmpfs", directory, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV, "mode=0755,size=1m"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(directory, 0); err != nil {
			t.Error("private fixture unmount failed", err)
		}
	})
	if err := os.Mkdir(filepath.Join(directory, "bin"), 0755); err != nil {
		t.Fatal(err)
	}
	var files []File
	for _, name := range []string{"one", "two"} {
		data := []byte("non-executable code-inspection fixture: " + name)
		if err := os.WriteFile(filepath.Join(directory, "bin", name), data, 0555); err != nil {
			t.Fatal(err)
		}
		files = append(files, File{Path: "bin/" + name, Mode: 0555, Size: int64(len(data)), SHA256: sha256.Sum256(data)})
	}
	if err := unix.Mount("", directory, "tmpfs", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "private-metadata-fixture")
	t.Cleanup(func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	})
	plan, err := NewPlan(files, nil)
	if err != nil {
		t.Fatal(err)
	}
	code, err := plan.prepareRetainedCode(context.Background(), root)
	if err != nil {
		t.Fatal("real read-only fixture preparation failed", err)
	}
	t.Cleanup(func() {
		if err := code.release(); err != nil {
			t.Error(err)
		}
	})
	return code
}

func retainedMetadataGuestAllowedQEMU() bool {
	if runtime.GOARCH != "arm" || os.Geteuid() != 0 {
		return false
	}
	model, modelErr := os.ReadFile("/sys/firmware/devicetree/base/model")
	commandLine, commandErr := os.ReadFile("/proc/cmdline")
	if modelErr != nil || commandErr != nil || string(model) != "ARM Versatile PB\x00" || len(commandLine) > 4096 {
		return false
	}
	for _, field := range bytes.Fields(commandLine) {
		if string(field) == "phantowd_code_owner_fixture=1" {
			return true
		}
	}
	return false
}

func TestRetainedMetadataFinalReadCancellationDiscardsCollectedTableQEMU(t *testing.T) {
	code := retainedMetadataRAMFixtureQEMU(t)
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelAfterHashCheckContext{Context: base, cancel: cancel, cancelAt: len(code.plan.nodes)}
	observation, err := code.nodeMetadata(ctx)
	if !errors.Is(base.Err(), context.Canceled) {
		t.Fatal("fixture did not cancel at the final metadata read")
	}
	if observation != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("final-read cancellation published a metadata table", len(observation), err)
	}
}

type countMetadataContextQEMU struct {
	context.Context
	checks int
}

func (c *countMetadataContextQEMU) Err() error {
	c.checks++
	return c.Context.Err()
}

func TestRetainedMetadataFinalReadCancellationRefusesActualPinsQEMU(t *testing.T) {
	code := retainedMetadataRAMFixtureQEMU(t)
	count := &countMetadataContextQEMU{Context: context.Background()}
	if _, err := code.plan.Inspect(count, code.root); err != nil {
		t.Fatal("independent complete-inspection control failed", err)
	}
	base, cancel := context.WithCancel(context.Background())
	defer cancel()
	// Complete Inspect makes the same checks in revalidate. Cancellation occurs
	// after the last successful pre-read metadata check, before its real syscalls.
	ctx := &cancelAfterHashCheckContext{Context: base, cancel: cancel,
		cancelAt: count.checks + len(code.plan.nodes)}
	err := code.revalidate(ctx)
	if !errors.Is(base.Err(), context.Canceled) || !errors.Is(err, context.Canceled) {
		t.Fatal("actual retained pins accepted final metadata cancellation", base.Err(), err)
	}
	// Refusal must neither consume the originals nor silently replace the table.
	for _, pin := range code.files {
		if _, err := pin.Stat(); err != nil {
			t.Fatal("refusal closed an original pin", err)
		}
	}
}

func TestRetainedMetadataComparisonPreservesOriginalTableAndDescriptorsQEMU(t *testing.T) {
	code := retainedMetadataRAMFixtureQEMU(t)
	original, err := code.nodeMetadata(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := code.verifyNodeMetadata(context.Background()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 32 {
		if err := code.verifyNodeMetadata(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) || !reflect.DeepEqual(code.metadata, original) {
		t.Fatal("comparison leaked descriptors or rewrote the original table", len(before), len(after), err)
	}
	collector := testing.AllocsPerRun(3, func() {
		if _, err := code.nodeMetadata(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	comparison := testing.AllocsPerRun(3, func() {
		if err := code.verifyNodeMetadata(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
	if comparison >= collector {
		t.Fatal("comparison did not remove transient metadata-table allocation", collector, comparison)
	}
	t.Logf("calculation-only collector_allocs=%.0f comparison_allocs=%.0f runtime_timing_qualified=false", collector, comparison)
}

func TestRetainedMetadataComparisonRefusesChangedOrIncompleteSnapshotQEMU(t *testing.T) {
	for _, kind := range []string{"changed-inode", "missing-node", "foreign-node-same-count"} {
		t.Run(kind, func(t *testing.T) {
			code := retainedMetadataRAMFixtureQEMU(t)
			switch kind {
			case "changed-inode":
				changed := code.metadata["bin/one"]
				changed.Ino++
				code.metadata["bin/one"] = changed
			case "missing-node":
				delete(code.metadata, "bin/one")
			case "foreign-node-same-count":
				code.metadata["foreign"] = code.metadata["bin/one"]
				delete(code.metadata, "bin/one")
			}
			if err := code.verifyNodeMetadata(context.Background()); !errors.Is(err, ErrMismatch) {
				t.Fatal("invalid original table was accepted", err)
			}
		})
	}
}
