// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/binary"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectUImageCommand(t *testing.T) {
	payload := []byte("synthetic zImage")
	fixture := make([]byte, 64+len(payload))
	header := fixture[:64]
	binary.BigEndian.PutUint32(header[0:4], 0x27051956)
	binary.BigEndian.PutUint32(header[8:12], 1_700_000_000)
	binary.BigEndian.PutUint32(header[12:16], uint32(len(payload)))
	binary.BigEndian.PutUint32(header[16:20], 0x00008000)
	binary.BigEndian.PutUint32(header[20:24], 0x00008000)
	binary.BigEndian.PutUint32(header[24:28], crc32.ChecksumIEEE(payload))
	copy(header[28:32], []byte{5, 2, 2, 0})
	copy(header[32:64], "Synthetic Linux")
	copy(fixture[64:], payload)
	binary.BigEndian.PutUint32(header[4:8], crc32.ChecksumIEEE(header))

	path := filepath.Join(t.TempDir(), "uImage")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-uimage", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"load_address": "0x00008000"`) || !strings.Contains(output.String(), `"valid": true`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

func TestDecodeMCUCommand(t *testing.T) {
	var output bytes.Buffer
	code, err := run([]string{"decode-mcu", "fa 23 00 00 00 00 fb"}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"PWRPush"`) || !strings.Contains(output.String(), `"unknown-not-validated"`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

func TestReplayHexCapture(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capture.hex")
	if err := os.WriteFile(path, []byte("# synthetic\nfa 23 00 00 00 00 fb\nfa 2a 00 00 00 00 fb # release\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"replay-mcu", "--format", "hex", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"frames": 2`) || !strings.Contains(output.String(), `"power": false`) {
		t.Fatalf("unexpected output: %s", output.String())
	}
}

func TestInspectRescueCommandRedactsIdentity(t *testing.T) {
	fixture := make([]byte, 2048+4)
	copy(fixture[0:20], "00:11:22:33:44:55")
	binary.LittleEndian.PutUint32(fixture[0x14:], 4)
	binary.LittleEndian.PutUint32(fixture[0x18:], 0x04030201)
	copy(fixture[0x32:], []byte{0x55, 0xaa, 'L', 'i', 'g', 'R', 'e', 's', 'c', 'u', 'r', 'e'})
	copy(fixture[0x3e:], []byte{0, 0x14, 0, 1, 1})
	copy(fixture[2048:], []byte{1, 2, 3, 4})
	path := filepath.Join(t.TempDir(), "rescue.bin")
	if err := os.WriteFile(path, fixture, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-rescue", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if !strings.Contains(output.String(), `"identity_redacted": true`) || strings.Contains(output.String(), "00:11:22") {
		t.Fatalf("identity was not redacted: %s", output.String())
	}
}

func TestInventoryRootfsCommandDoesNotExposeHostRoot(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "release"), []byte("synthetic\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inventory-rootfs", "--summary", root}, &output)
	if err != nil || code != 0 {
		t.Fatalf("code=%d err=%v", code, err)
	}
	if strings.Contains(output.String(), filepath.ToSlash(root)) || !strings.Contains(output.String(), `"regular_files": 1`) {
		t.Fatalf("unexpected rootfs inventory output: %s", output.String())
	}
}

func TestRejectsNonRegularInput(t *testing.T) {
	if _, _, err := openRegular(t.TempDir()); err == nil {
		t.Fatal("directory input was accepted")
	}
}

func TestInvalidCommand(t *testing.T) {
	if code, err := run([]string{"write-flash"}, &bytes.Buffer{}); code == 0 || err == nil {
		t.Fatal("unknown mutation command was accepted")
	}
}
