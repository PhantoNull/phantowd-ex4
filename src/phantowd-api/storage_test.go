// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
)

func TestCollectStorageReportsSysfsOnlyObservations(t *testing.T) {
	snapshot, err := collectStorage(fixtureSysfs())
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.Scope != "kernel-sysfs-only" ||
		!snapshot.InventoryReadOnly || snapshot.MutationsPerformed || snapshot.StableIdentityAvailable {
		t.Fatalf("incorrect storage safety boundary: %+v", snapshot)
	}
	if snapshot.DeviceCount != 2 || len(snapshot.Observations) != 2 {
		t.Fatalf("expected one disk node and one partition node: %+v", snapshot)
	}
	disk, partition := snapshot.Observations[0], snapshot.Observations[1]
	if disk.Name != "sda" || disk.Kind != "block" || disk.Major != 8 || disk.Minor != 0 ||
		disk.SizeBytes != 1<<30 || disk.ReadOnly || disk.Removable {
		t.Fatalf("incorrect whole-block observation: %+v", disk)
	}
	if disk.SerialStatus != identityPresent || disk.WWNStatus != identityPresent {
		t.Fatalf("valid synthetic SCSI identity pages not detected: %+v", disk)
	}
	if partition.Name != "sda1" || partition.Kind != "partition" || partition.PartitionNumber != 1 ||
		partition.Major != 8 || partition.Minor != 1 || partition.SizeBytes != (1<<30)-512 || !partition.ReadOnly {
		t.Fatalf("incorrect partition observation: %+v", partition)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"fixture-secret", "PHANTOWD-QEMU-SERIAL-01", "500f000000000001", "fixture-fs-uuid-a", "fixture-partuuid-a"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("observation exposed identity material %q: %s", forbidden, encoded)
		}
	}
}

func TestSCSIVPDIdentityParsing(t *testing.T) {
	serialPage := makeVPDPage(0x80, []byte("PHANTOWD-QEMU-SERIAL-01"))
	if status := parseSerialVPDPage(serialPage); status != identityPresent {
		t.Fatalf("valid serial VPD page status = %q", status)
	}
	if status := parseSerialVPDPage(makeVPDPage(0x80, []byte("   "))); status != identityInvalid {
		t.Fatalf("empty serial accepted with status %q", status)
	}
	if status := parseSerialVPDPage(makeVPDPage(0x80, []byte("serial\x00invalid"))); status != identityInvalid {
		t.Fatalf("non-printable serial accepted with status %q", status)
	}

	naa := []byte{0x50, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	page := makeVPDPage(0x83, append([]byte{0x01, 0x03, 0x00, byte(len(naa))}, naa...))
	if got, status := parseNAAWWNPage(page); status != identityPresent || got != "naa.500f000000000001" {
		t.Fatalf("valid NAA page parsed as %q, %q", got, status)
	}

	t.Run("NAA type and width", func(t *testing.T) {
		for _, test := range []struct {
			name       string
			firstByte  byte
			width      int
			wantStatus identityStatus
		}{
			{name: "NAA 2 eight-byte", firstByte: 0x20, width: 8, wantStatus: identityPresent},
			{name: "NAA 3 eight-byte", firstByte: 0x30, width: 8, wantStatus: identityPresent},
			{name: "NAA 5 eight-byte", firstByte: 0x50, width: 8, wantStatus: identityPresent},
			{name: "NAA 6 sixteen-byte", firstByte: 0x60, width: 16, wantStatus: identityPresent},
			{name: "reserved NAA 4", firstByte: 0x40, width: 8, wantStatus: identityInvalid},
			{name: "NAA 6 wrong width", firstByte: 0x60, width: 8, wantStatus: identityInvalid},
			{name: "NAA 5 wrong width", firstByte: 0x50, width: 16, wantStatus: identityInvalid},
		} {
			t.Run(test.name, func(t *testing.T) {
				identifier := make([]byte, test.width)
				identifier[0] = test.firstByte
				_, status := parseNAAWWNPage(makeNAAPage(identifier))
				if status != test.wantStatus {
					t.Fatalf("identifier type/width got %q, want %q", status, test.wantStatus)
				}
			})
		}
	})

	t.Run("duplicate matching designator", func(t *testing.T) {
		payload := append([]byte{0x01, 0x03, 0x00, byte(len(naa))}, naa...)
		payload = append(payload, 0x01, 0x03, 0x00, byte(len(naa)))
		payload = append(payload, naa...)
		if got, status := parseNAAWWNPage(makeVPDPage(0x83, payload)); status != identityPresent || got != "naa.500f000000000001" {
			t.Fatalf("matching duplicate not collapsed: %q, %q", got, status)
		}
	})

	t.Run("conflicting designators", func(t *testing.T) {
		other := []byte{0x50, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02}
		payload := append([]byte{0x01, 0x03, 0x00, byte(len(naa))}, naa...)
		payload = append(payload, 0x01, 0x03, 0x00, byte(len(other)))
		payload = append(payload, other...)
		if got, status := parseNAAWWNPage(makeVPDPage(0x83, payload)); status != identityAmbiguous || got != "" {
			t.Fatalf("conflicting identities were not rejected: %q, %q", got, status)
		}
	})

	t.Run("zero NAA rejected", func(t *testing.T) {
		zero := make([]byte, 8)
		payload := append([]byte{0x01, 0x03, 0x00, byte(len(zero))}, zero...)
		if got, status := parseNAAWWNPage(makeVPDPage(0x83, payload)); status != identityInvalid || got != "" {
			t.Fatalf("zero NAA accepted: %q, %q", got, status)
		}
	})

	for _, test := range []struct {
		name string
		page []byte
	}{
		{name: "wrong page code", page: makeVPDPage(0x80, []byte("id"))},
		{name: "truncated descriptor", page: []byte{0, 0x83, 0, 8, 1, 3, 0, 8, 0}},
		{name: "descriptor overrun", page: makeVPDPage(0x83, []byte{1, 3, 0, 8, 1, 2})},
		{name: "invalid NAA size", page: makeVPDPage(0x83, []byte{1, 3, 0, 7, 1, 2, 3, 4, 5, 6, 7})},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, status := parseNAAWWNPage(test.page); status != identityInvalid {
				t.Fatalf("malformed page accepted with status %q", status)
			}
		})
	}
}

func TestCollectStorageIdentityStatusesFailClosed(t *testing.T) {
	for _, test := range []struct {
		name        string
		serialPage  []byte
		wwnPage     []byte
		serialState identityStatus
		wwnState    identityStatus
	}{
		{name: "missing optional pages", serialState: identityUnavailable, wwnState: identityUnavailable},
		{name: "invalid pages", serialPage: []byte{0, 0x80, 0, 20, 'x'}, wwnPage: []byte{0, 0x83, 0, 8, 1, 3}, serialState: identityInvalid, wwnState: identityInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			sysfs := fixtureSysfs()
			delete(sysfs, "class/block/sda/device/vpd_pg80")
			delete(sysfs, "class/block/sda/device/vpd_pg83")
			if test.serialPage != nil {
				sysfs["class/block/sda/device/vpd_pg80"] = &fstest.MapFile{Data: test.serialPage}
			}
			if test.wwnPage != nil {
				sysfs["class/block/sda/device/vpd_pg83"] = &fstest.MapFile{Data: test.wwnPage}
			}
			snapshot, err := collectStorage(sysfs)
			if err != nil {
				t.Fatal(err)
			}
			if snapshot.Observations[0].SerialStatus != test.serialState || snapshot.Observations[0].WWNStatus != test.wwnState {
				t.Fatalf("unexpected fail-closed identity states: %+v", snapshot.Observations[0])
			}
		})
	}
}

func TestCollectStorageAllowsEmptySysfsInventory(t *testing.T) {
	snapshot, err := collectStorage(fstest.MapFS{
		"class":       {Mode: fs.ModeDir | 0o555},
		"class/block": {Mode: fs.ModeDir | 0o555},
	})
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.DeviceCount != 0 || snapshot.Observations == nil {
		t.Fatalf("empty inventory should be represented explicitly: %+v", snapshot)
	}
}

func TestCollectStorageRejectsMalformedOrUnboundedSysfs(t *testing.T) {
	for _, test := range []struct {
		name  string
		field string
		value string
	}{
		{name: "invalid device number", field: "dev", value: "8:not-a-number\n"},
		{name: "invalid sector count", field: "size", value: "unknown\n"},
		{name: "sector-byte overflow", field: "size", value: "18446744073709551615\n"},
		{name: "invalid read-only flag", field: "ro", value: "2\n"},
		{name: "invalid removable flag", field: "removable", value: "yes\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			sysfs := fixtureSysfs()
			sysfs["class/block/sda/"+test.field] = &fstest.MapFile{Data: []byte(test.value)}
			if _, err := collectStorage(sysfs); err == nil {
				t.Fatal("invalid sysfs observation accepted")
			}
		})
	}

	t.Run("partition number", func(t *testing.T) {
		sysfs := fixtureSysfs()
		sysfs["class/block/sda1/partition"] = &fstest.MapFile{Data: []byte("0\n")}
		if _, err := collectStorage(sysfs); err == nil {
			t.Fatal("zero partition number accepted")
		}
	})

	t.Run("too many entries", func(t *testing.T) {
		sysfs := make(fstest.MapFS)
		sysfs["class"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
		sysfs["class/block"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
		for i := 0; i < maxBlockEntries+1; i++ {
			name := fmt.Sprintf("fake%02d", i)
			sysfs["class/block/"+name] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
			sysfs["class/block/"+name+"/dev"] = &fstest.MapFile{Data: []byte("8:0\n")}
			sysfs["class/block/"+name+"/size"] = &fstest.MapFile{Data: []byte("1\n")}
			sysfs["class/block/"+name+"/ro"] = &fstest.MapFile{Data: []byte("0\n")}
			sysfs["class/block/"+name+"/removable"] = &fstest.MapFile{Data: []byte("0\n")}
		}
		if _, err := collectStorage(sysfs); err == nil {
			t.Fatal("unbounded sysfs inventory accepted")
		}
	})
}

func TestParseStorageSectorCount(t *testing.T) {
	if got, err := parseSectorBytes("2048\n"); err != nil || got != 1<<20 {
		t.Fatalf("valid Linux sector count failed: bytes=%d err=%v", got, err)
	}
	if _, err := parseSectorBytes(strings.Repeat("9", 40)); err == nil {
		t.Fatal("overflowing sector count accepted")
	}
	if _, err := parseSectorBytes("18446744073709551615"); err == nil {
		t.Fatal("sector multiplication overflow accepted")
	}
}

func fixtureSysfs() fstest.MapFS {
	return fstest.MapFS{
		"class":                           {Mode: fs.ModeDir | 0o555},
		"class/block":                     {Mode: fs.ModeDir | 0o555},
		"class/block/sda":                 {Mode: fs.ModeDir | 0o555},
		"class/block/sda/dev":             {Data: []byte("8:0\n")},
		"class/block/sda/size":            {Data: []byte("2097152\n")},
		"class/block/sda/ro":              {Data: []byte("0\n")},
		"class/block/sda/removable":       {Data: []byte("0\n")},
		"class/block/sda/device":          {Mode: fs.ModeDir | 0o555},
		"class/block/sda/device/vpd_pg80": {Data: makeVPDPage(0x80, []byte("PHANTOWD-QEMU-SERIAL-01"))},
		"class/block/sda/device/vpd_pg83": {Data: makeVPDPage(0x83, []byte{0x01, 0x03, 0x00, 0x08, 0x50, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})},
		"class/block/sda1":                {Mode: fs.ModeDir | 0o555},
		"class/block/sda1/dev":            {Data: []byte("8:1\n")},
		"class/block/sda1/size":           {Data: []byte("2097151\n")},
		"class/block/sda1/ro":             {Data: []byte("1\n")},
		"class/block/sda1/removable":      {Data: []byte("0\n")},
		"class/block/sda1/partition":      {Data: []byte("1\n")},
	}
}

func makeVPDPage(code byte, payload []byte) []byte {
	return append([]byte{0, code, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func makeNAAPage(identifier []byte) []byte {
	payload := append([]byte{0x01, 0x03, 0x00, byte(len(identifier))}, identifier...)
	return makeVPDPage(0x83, payload)
}
