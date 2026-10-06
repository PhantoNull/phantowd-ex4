//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mdmetadata

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestInspectBlockRejectsRegularFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "not-a-block-device")
	if err := os.WriteFile(path, make([]byte, 64*1024), 0600); err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	_, err = InspectBlock(source, volumeprobe.BlockDeviceGeneration{Major: 8, Minor: 16, DiskSequence: 1}, 64*1024,
		Partition{Number: 1, StartLBA: 16, SizeLBA: 64})
	if !errors.Is(err, ErrUnsafeSource) {
		t.Fatalf("regular file was not refused as a live block descriptor: %v", err)
	}
}
