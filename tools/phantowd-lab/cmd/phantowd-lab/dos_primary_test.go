// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInspectDOSPrimaryCommandReadsMetadataWithoutWriting(t *testing.T) {
	image := make([]byte, 128*512)
	copy(image, "private-bootstrap-data")
	binary.LittleEndian.PutUint32(image[440:], 0xdeadbeef)
	image[510], image[511] = 0x55, 0xaa
	entry := image[462:478]
	entry[0], entry[4] = 0x80, 0xfd
	binary.LittleEndian.PutUint32(entry[8:], 40)
	binary.LittleEndian.PutUint32(entry[12:], 10)
	path := filepath.Join(t.TempDir(), "private-layout.img")
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-dos-primary-image", path}, &output)
	if err != nil || code != 0 {
		t.Fatalf("DOS primary observation: code=%d err=%v output=%s", code, err, output.String())
	}
	for _, want := range []string{`"status": "observed-dos-primary"`, `"partition_count": 1`, `"number": 2`, `"type_code": "fd"`, `"first_lba": 40`, `"last_lba": 49`, `"size_bytes": 5120`, `"wd_compatibility": "unqualified"`, `"mutations_performed": false`, `"assembly_performed": false`, `"mount_performed": false`} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("missing %s: %s", want, output.String())
		}
	}
	for _, private := range []string{path, "private-layout", "deadbeef", "private-bootstrap-data"} {
		if strings.Contains(output.String(), private) {
			t.Fatalf("private input returned: %s", output.String())
		}
	}
	after, err := os.ReadFile(path)
	if err != nil || sha256.Sum256(after) != sha256.Sum256(image) {
		t.Fatal("input image changed", err)
	}
}

func TestInspectDOSPrimaryCommandRefusesUnsupportedAndNonRegularInput(t *testing.T) {
	path := filepath.Join(t.TempDir(), "unsupported.img")
	image := make([]byte, 64*512)
	image[510], image[511] = 0x55, 0xaa
	image[450] = 0x05
	binary.LittleEndian.PutUint32(image[454:], 16)
	binary.LittleEndian.PutUint32(image[458:], 8)
	if err := os.WriteFile(path, image, 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	code, err := run([]string{"inspect-dos-primary-image", path}, &output)
	if err != nil || code != 2 || !strings.Contains(output.String(), `"status": "unsupported"`) || !strings.Contains(output.String(), `"partitions": []`) {
		t.Fatal("unsupported layout was admitted", code, err, output.String())
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(after, image) {
		t.Fatal("refusal changed image", err)
	}
	for _, args := range [][]string{{"inspect-dos-primary-image"}, {"inspect-dos-primary-image", filepath.Dir(path)}, {"inspect-dos-primary-image", path, "extra"}} {
		output.Reset()
		code, err = run(args, &output)
		if err == nil || code != 1 || output.Len() != 0 {
			t.Fatal("invalid input produced metadata", args, code, err, output.String())
		}
	}
}
