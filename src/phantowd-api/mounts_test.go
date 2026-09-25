// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func TestCollectMountInventoryReadOnlyAndRedacted(t *testing.T) {
	const mountinfo = "" +
		"36 0 8:0 / /media/data rw,relatime - ext4 /dev/sda1 rw,errors=continue\n" +
		"37 36 0:42 / /proc ro,nosuid,nodev,noexec,relatime - proc proc rw\n" +
		"38 36 253:0 /root /mnt/media\\040archive ro,relatime shared:1 - xfs /dev/md0 rw\n"
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.FixedZone("test", 3600))
	snapshot, err := collectMountInventory(fstest.MapFS{"self/mountinfo": {Data: []byte(mountinfo)}}, now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.Scope != "current-process-mount-namespace" ||
		!snapshot.ReadOnly || snapshot.FilesystemContentsRead || snapshot.MountOperationsPerformed ||
		!snapshot.ObservedAt.Equal(now.UTC()) || snapshot.MountCount != 3 || len(snapshot.Mounts) != 3 {
		t.Fatalf("unsafe or incomplete mount snapshot: %+v", snapshot)
	}
	if first := snapshot.Mounts[0]; first.MountPoint != "/media/data" || first.Filesystem != "ext4" ||
		first.DeviceMajor != 8 || first.DeviceMinor != 0 || first.ReadOnly {
		t.Fatalf("unexpected writable data mount observation: %+v", first)
	}
	if second := snapshot.Mounts[1]; second.MountPoint != "/mnt/media archive" || second.Filesystem != "xfs" ||
		second.DeviceMajor != 253 || second.DeviceMinor != 0 || !second.ReadOnly {
		t.Fatalf("escaped mountpoint/read-only state was not parsed: %+v", second)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"/dev/sda1", "/dev/md0", "errors=continue", "nosuid", "/root"} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("mount API leaked source/options/root value %q: %s", secret, encoded)
		}
	}
}

func TestParseMountInfoRejectsMalformedOrUnboundedInput(t *testing.T) {
	validLine := "36 35 8:0 / /data rw,relatime - ext4 /dev/sda1 rw"
	tooManyLines := make([]string, maxMountEntries+1)
	for i := range tooManyLines {
		tooManyLines[i] = fmt.Sprintf("%d %d 8:0 / /data rw - ext4 /dev/sda1 rw", i+1, i+1)
	}
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "empty", data: ""},
		{name: "malformed separator", data: "36 35 8:0 / /data rw ext4 /dev/sda1 rw\n"},
		{name: "invalid device number", data: "36 35 8:x / /data rw - ext4 /dev/sda1 rw\n"},
		{name: "invalid filesystem root", data: "36 35 8:0 relative /data rw - ext4 /dev/sda1 rw\n"},
		{name: "no access mode", data: "36 35 8:0 / /data relatime - ext4 /dev/sda1 rw\n"},
		{name: "contradictory access modes", data: "36 35 8:0 / /data ro,rw - ext4 /dev/sda1 rw\n"},
		{name: "invalid escaped path", data: "36 35 8:0 / /bad\\04 rw - ext4 /dev/sda1 rw\n"},
		{name: "duplicate mount ID", data: validLine + "\n" + validLine + "\n"},
		{name: "oversized line", data: "36 35 8:0 / /data rw - ext4 " + strings.Repeat("x", maxMountLineBytes) + " rw\n"},
		{name: "too many records", data: strings.Join(tooManyLines, "\n") + "\n"},
		{name: "too many bytes", data: strings.Repeat("x", maxProcBytes+1)},
		{name: "invalid field count", data: "36 35 8:0 / /data rw - ext4\n"},
		{name: "invalid filesystem token", data: "36 35 8:0 / /data rw - ext4/../../bad /dev/sda1 rw\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseMountInfo(test.data); err == nil {
				t.Fatal("malformed or unbounded mount information accepted")
			}
		})
	}
}

func FuzzParseMountInfo(f *testing.F) {
	f.Add("36 35 8:0 / /data rw,relatime - ext4 /dev/sda1 rw\n")
	f.Add("37 36 0:42 / /proc ro,nosuid,nodev - proc proc rw\n")
	f.Add("38 36 253:0 / /mnt/media\\040archive ro,relatime shared:1 - xfs /dev/md0 rw\n")
	f.Add("")
	f.Fuzz(func(t *testing.T, data string) {
		observations, err := parseMountInfo(data)
		if err != nil {
			return
		}
		if len(observations) == 0 || len(observations) > maxMountEntries {
			t.Fatalf("accepted mount count outside bounds: %d", len(observations))
		}
		for _, observation := range observations {
			if observation.MountPoint == "" || observation.MountPoint[0] != '/' ||
				!validMountFilesystem(observation.Filesystem) {
				t.Fatalf("accepted invalid observation: %+v", observation)
			}
		}
	})
}
