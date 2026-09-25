// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"fmt"
	"io/fs"
	"testing"
	"testing/fstest"
	"time"
)

func TestCollectMDArrayInventoryReadOnly(t *testing.T) {
	proc := fstest.MapFS{
		"mdstat": {Data: []byte("Personalities : [raid1]\nmd0 : active raid1 sda2[0] sdb2[1]\n      20958464 blocks super 1.2 [2/2] [UU]\nmd1 : active raid1 sda3[0] sdb3[1](F)\n      1024 blocks super 1.2 [2/1] [U_]\n      [=====>........] recovery =  40.0% (800/2000) finish=1.0min speed=20K/sec\nunused devices: <none>\n")},
	}
	sysfs := fixtureMDArraySysfs("md0", "md1")
	now := time.Date(2026, 9, 25, 12, 0, 0, 0, time.FixedZone("test", 3600))
	snapshot := collectMDArrayInventory(proc, sysfs, now)
	if snapshot.Status != arrayInventoryAvailable || snapshot.SchemaVersion != 1 || !snapshot.ReadOnly || snapshot.BlockDevicesOpened || snapshot.DiskContentRead || snapshot.MutationsPerformed {
		t.Fatalf("unsafe or incomplete inventory envelope: %+v", snapshot)
	}
	if !snapshot.ObservedAt.Equal(now.UTC()) || snapshot.ArrayCount != 2 || len(snapshot.Arrays) != 2 {
		t.Fatalf("unexpected inventory metadata: %+v", snapshot)
	}
	if first := snapshot.Arrays[0]; first.Name != "md0" || first.Level != "raid1" || first.State != "clean" || first.ExpectedDevices != 2 || first.ActiveDevices != 2 || first.DegradedDevices != 0 || first.Health != arrayHealthHealthy || first.SyncAction != "idle" || len(first.Members) != 2 || first.Members[0].Name != "sda2" {
		t.Fatalf("unexpected healthy array observation: %+v", first)
	}
	if second := snapshot.Arrays[1]; second.Name != "md1" || second.Health != arrayHealthDegraded || second.DegradedDevices != 1 || second.SyncAction != "recover" || second.SyncProgressPercent == nil || *second.SyncProgressPercent != 40 || second.Members[1].State != "faulty" {
		t.Fatalf("unexpected degraded/recovery observation: %+v", second)
	}
}

func TestCollectMDArrayInventoryStates(t *testing.T) {
	t.Run("empty supported inventory", func(t *testing.T) {
		snapshot := collectMDArrayInventory(fstest.MapFS{
			"mdstat": {Data: []byte("Personalities : [raid1]\nunused devices: <none>\n")},
		}, emptySysfs(), time.Now())
		if snapshot.Status != arrayInventoryAvailable || snapshot.ArrayCount != 0 || snapshot.Arrays == nil {
			t.Fatalf("empty inventory was not explicit: %+v", snapshot)
		}
	})

	t.Run("unsupported proc source", func(t *testing.T) {
		snapshot := collectMDArrayInventory(fstest.MapFS{}, emptySysfs(), time.Now())
		if snapshot.Status != arrayInventoryUnsupported || snapshot.Arrays == nil || len(snapshot.Arrays) != 0 {
			t.Fatalf("missing mdstat was misreported: %+v", snapshot)
		}
	})

	t.Run("sysfs array without proc source is partial", func(t *testing.T) {
		snapshot := collectMDArrayInventory(fstest.MapFS{}, fixtureMDArraySysfs("md0"), time.Now())
		if snapshot.Status != arrayInventoryPartial || len(snapshot.Arrays) != 1 || snapshot.Arrays[0].Health != arrayHealthUnknown {
			t.Fatalf("sysfs-only array produced a false healthy claim: %+v", snapshot)
		}
	})

	t.Run("missing sysfs node is partial, never healthy", func(t *testing.T) {
		proc := fstest.MapFS{"mdstat": {Data: []byte("md0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\n")}}
		snapshot := collectMDArrayInventory(proc, emptySysfs(), time.Now())
		if snapshot.Status != arrayInventoryPartial || len(snapshot.Arrays) != 1 || snapshot.Arrays[0].Health != arrayHealthUnknown {
			t.Fatalf("missing sysfs node produced a false health claim: %+v", snapshot)
		}
	})
}

func TestParseMDStatRejectsMalformedOrUnboundedInput(t *testing.T) {
	for _, test := range []struct {
		name string
		data string
	}{
		{name: "unknown array state", data: "md0 : recovering raid1 sda2[0]\n"},
		{name: "invalid device counts", data: "md0 : active raid1 sda2[0]\n      1 blocks [2/3] [UU]\n"},
		{name: "invalid progress", data: "md0 : active raid1 sda2[0]\n      [===>] recovery = NaN%\n"},
		{name: "invalid member", data: "md0 : active raid1 sda2[not-an-index]\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseMDStat(test.data); err == nil {
				t.Fatal("malformed mdstat input accepted")
			}
		})
	}

	tooMany := ""
	for i := 0; i < maxMDArrayEntries+1; i++ {
		tooMany += fmt.Sprintf("md%d : inactive\n", i)
	}
	if _, err := parseMDStat(tooMany); err == nil {
		t.Fatal("unbounded array count accepted")
	}
	if _, err := parseMDStat(string(make([]byte, maxProcBytes+1))); err == nil {
		t.Fatal("unbounded mdstat accepted")
	}
}

func emptySysfs() fstest.MapFS {
	return fstest.MapFS{
		"class":       {Mode: fs.ModeDir | 0o555},
		"class/block": {Mode: fs.ModeDir | 0o555},
	}
}

func fixtureMDArraySysfs(names ...string) fstest.MapFS {
	sysfs := emptySysfs()
	for _, name := range names {
		base := "class/block/" + name
		members := []string{"sda2", "sdb2"}
		if name == "md1" {
			members = []string{"sda3", "sdb3"}
		}
		sysfs[base] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
		sysfs[base+"/md"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
		sysfs[base+"/md/level"] = &fstest.MapFile{Data: []byte("raid1\n")}
		sysfs[base+"/md/array_state"] = &fstest.MapFile{Data: []byte("clean\n")}
		sysfs[base+"/md/degraded"] = &fstest.MapFile{Data: []byte("0\n")}
		sysfs[base+"/md/raid_disks"] = &fstest.MapFile{Data: []byte("2\n")}
		sysfs[base+"/md/sync_action"] = &fstest.MapFile{Data: []byte("idle\n")}
		sysfs[base+"/md/sync_completed"] = &fstest.MapFile{Data: []byte("0 / 0\n")}
		sysfs[base+"/slaves"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
		for _, member := range members {
			sysfs[base+"/slaves/"+member] = &fstest.MapFile{Mode: fs.ModeIrregular}
		}
		if name == "md1" {
			sysfs[base+"/md/array_state"] = &fstest.MapFile{Data: []byte("active\n")}
			sysfs[base+"/md/degraded"] = &fstest.MapFile{Data: []byte("1\n")}
			sysfs[base+"/md/sync_action"] = &fstest.MapFile{Data: []byte("recover\n")}
			sysfs[base+"/md/sync_completed"] = &fstest.MapFile{Data: []byte("800 / 2000\n")}
		}
	}
	return sysfs
}
