//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"os"
	"path/filepath"
	"testing"
)

func TestQEMUCollisionFixture(t *testing.T) {
	h := qemuXFSProbeHeader()
	if len(h) != 512 || string(h[:4]) != "XFSB" || binary.BigEndian.Uint32(h[4:]) != 4096 ||
		binary.BigEndian.Uint64(h[8:]) != 4096 || !bytes.Equal(h[120:125], []byte{12, 9, 8, 4, 12}) {
		t.Fatal("probe-only XFS geometry")
	}
	for offset, want := range map[int]uint16{100: 4, 102: 512, 104: 256, 106: 16} {
		if binary.BigEndian.Uint16(h[offset:]) != want {
			t.Fatalf("XFS geometry at %d", offset)
		}
	}
	if !bytes.Equal(h, qemuXFSProbeHeader()) {
		t.Fatal("nondeterministic header")
	}
	h[0] = 0
	if qemuXFSProbeHeader()[0] != 'X' {
		t.Fatal("header backing memory escaped")
	}
	image, err := os.Create(filepath.Join(t.TempDir(), "probe-image"))
	if err != nil {
		t.Fatal(err)
	}
	defer image.Close()
	if _, err := qemuProbeImageHash(image); err == nil {
		t.Fatal("short image hashed as complete")
	}
	if err := image.Truncate(16 * 1024 * 1024); err != nil {
		t.Fatal(err)
	}
	before, err := qemuProbeImageHash(image)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := image.Seek(1234, 0); err != nil {
		t.Fatal(err)
	}
	after, err := qemuProbeImageHash(image)
	if err != nil || before != after {
		t.Fatal("hash depended on shared offset", err)
	}
	if offset, err := image.Seek(0, 1); err != nil || offset != 1234 {
		t.Fatal("hash moved shared offset", offset, err)
	}
	if _, err := image.WriteAt([]byte{1}, 16*1024*1024-1); err != nil {
		t.Fatal(err)
	}
	after, err = qemuProbeImageHash(image)
	if err != nil || before == after {
		t.Fatal("hash missed last-byte modification", err)
	}
}
