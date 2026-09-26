//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"reflect"
	"strings"
	"testing"
	"testing/fstest"
)

func TestQEMUNFSFixture(t *testing.T) {
	p, err := qemuNFSFixture()
	if err != nil || len(p.Exports) != 3 {
		t.Fatal("fixture", err)
	}
	for _, text := range []string{`RW\040\0431\040\042quoted\042`, "127.0.0.1/32(ro,", "192.0.2.1/32(rw,", "anonuid=101000,anongid=101000"} {
		if !strings.Contains(p.Table, text) {
			t.Fatalf("missing fixture contract %q", text)
		}
	}
	again, err := qemuNFSFixture()
	if err != nil || !reflect.DeepEqual(p, again) {
		t.Fatal("nondeterministic fixture")
	}
	if err := runQEMUNFSTest("unrecognized"); err == nil {
		t.Fatal("unknown fixture mode accepted")
	}
	for _, name := range []string{"valid", "wrong serial", "wrong WWN", "missing page", "truncated page"} {
		t.Run(name, func(t *testing.T) {
			serialName, wwnName := "class/block/sdb/device/vpd_pg80", "class/block/sdb/device/vpd_pg83"
			data := fstest.MapFS{
				serialName: {Data: makeVPDPage(0x80, []byte(qemuDataSerial))},
				wwnName:    {Data: makeNAAPage([]byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})},
			}
			switch name {
			case "wrong serial":
				data[serialName].Data = makeVPDPage(0x80, []byte(qemuTestSerial))
			case "wrong WWN":
				data[wwnName].Data = makeNAAPage([]byte{0x50, 0x0f, 0, 0, 0, 0, 0, 1})
			case "missing page":
				delete(data, serialName)
			case "truncated page":
				data[serialName].Data = []byte{0, 0x80, 0}
			}
			if err := verifyQEMUNFSDevice(data); (err == nil) != (name == "valid") {
				t.Fatal("fixture identity guard", err)
			}
		})
	}
}
