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
	first := snapshot.Arrays[0]
	if first.Name != "md0" || first.Level != "raid1" || first.State != "clean" || first.ExpectedDevices != 2 || first.ActiveDevices != 2 || first.DegradedDevices != 0 || first.Health != arrayHealthHealthy || first.SyncAction != "idle" || len(first.Members) != 2 || first.Members[0].Name != "sda2" {
		t.Fatalf("unexpected healthy array observation: %+v", first)
	}
	if !snapshot.identityInventoryComplete || first.uuidStatus != identityPresent || first.arrayUUID != "11111111-2222-3333-4444-555555555555" {
		t.Fatalf("complete sysfs inventory did not provide a private stable array identity: %+v", first)
	}
	if second := snapshot.Arrays[1]; second.Name != "md1" || second.Health != arrayHealthDegraded || second.DegradedDevices != 1 || second.SyncAction != "recover" || second.SyncProgressPercent == nil || *second.SyncProgressPercent != 40 || second.Members[1].State != "faulty" {
		t.Fatalf("unexpected degraded/recovery observation: %+v", second)
	}
}

func TestMDArrayUUIDMatchingRequiresCompleteInventoryAndDistinguishesClones(t *testing.T) {
	proc := fstest.MapFS{"mdstat": {Data: []byte("md0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\nmd1 : active raid1 sda3[0] sdb3[1]\n      1024 blocks super 1.2 [2/2] [UU]\n")}}
	const uuid = "11111111-2222-3333-4444-555555555555"
	sysfs := fixtureMDArraySysfs("md0", "md1")
	sysfs["class/block/md1/md/uuid"] = &fstest.MapFile{Data: []byte("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n")}
	snapshot := collectMDArrayInventory(proc, sysfs, time.Now())
	if match, err := matchMDArrayUUID(snapshot, uuid); err != nil || match.State != "one-object" || len(match.ArrayIndices) != 1 || match.ArrayIndices[0] != 0 {
		t.Fatalf("complete inventory did not resolve its unique MD UUID: %+v, %v", match, err)
	}
	subset := snapshot
	subset.Arrays = subset.Arrays[:1]
	if _, err := matchMDArrayUUID(subset, uuid); err == nil {
		t.Fatal("selected array subset was accepted as the complete inventory")
	}

	cloned := fixtureMDArraySysfs("md0", "md1")
	cloned["class/block/md1/md/uuid"] = &fstest.MapFile{Data: []byte(uuid + "\n")}
	cloneSnapshot := collectMDArrayInventory(proc, cloned, time.Now())
	if !cloneSnapshot.identityInventoryComplete || cloneSnapshot.Arrays[0].uuidStatus != identityAmbiguous || cloneSnapshot.Arrays[1].uuidStatus != identityAmbiguous {
		t.Fatalf("duplicate array UUIDs were not marked ambiguous: %+v", cloneSnapshot.Arrays)
	}
	if match, err := matchMDArrayUUID(cloneSnapshot, uuid); err != nil || match.State != "conflicting-objects" || len(match.ArrayIndices) != 2 {
		t.Fatalf("duplicate MD UUIDs were not resolved as distinct conflicting objects: %+v, %v", match, err)
	}

	alias := fixtureMDArraySysfs("md0", "md1")
	alias["class/block/md1/dev"] = &fstest.MapFile{Data: []byte("9:0\n")}
	alias["class/block/md1/md/uuid"] = &fstest.MapFile{Data: []byte(uuid + "\n")}
	aliasSnapshot := collectMDArrayInventory(proc, alias, time.Now())
	if match, err := matchMDArrayUUID(aliasSnapshot, uuid); err != nil || match.State != "one-object" || len(match.ArrayIndices) != 2 {
		t.Fatalf("aliases of one major/minor object were misclassified as clones: %+v, %v", match, err)
	}

	conflictingAlias := fixtureMDArraySysfs("md0", "md1")
	conflictingAlias["class/block/md1/dev"] = &fstest.MapFile{Data: []byte("9:0\n")}
	conflictingAliasSnapshot := collectMDArrayInventory(proc, conflictingAlias, time.Now())
	if conflictingAliasSnapshot.identityInventoryComplete {
		t.Fatal("one kernel object with conflicting observed MD UUIDs was treated as complete")
	}
	if _, err := matchMDArrayUUID(conflictingAliasSnapshot, uuid); err == nil {
		t.Fatal("one kernel object with conflicting MD UUID observations was resolved")
	}

	incomplete := fixtureMDArraySysfs("md0", "md1")
	delete(incomplete, "class/block/md1/md/uuid")
	incompleteSnapshot := collectMDArrayInventory(proc, incomplete, time.Now())
	if incompleteSnapshot.identityInventoryComplete || incompleteSnapshot.Arrays[0].uuidStatus != identityUnavailable || incompleteSnapshot.Arrays[0].arrayUUID != "" {
		t.Fatalf("incomplete inventory leaked a one-array uniqueness claim: %+v", incompleteSnapshot)
	}
	if _, err := matchMDArrayUUID(incompleteSnapshot, uuid); err == nil {
		t.Fatal("caller-visible array subset was accepted as a complete identity inventory")
	}

	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), uuid) || strings.Contains(string(encoded), "arrayUUID") || strings.Contains(string(encoded), "identityInventoryComplete") {
		t.Fatalf("private array identity escaped in JSON: %s", encoded)
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

func TestCollectMDArrayInventoryAcceptsNoActiveSyncProgress(t *testing.T) {
	proc := fstest.MapFS{
		"mdstat": {Data: []byte("Personalities : [raid1]\nmd0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\nunused devices: <none>\n")},
	}
	sysfs := fixtureMDArraySysfs("md0")
	sysfs["class/block/md0/md/sync_completed"] = &fstest.MapFile{Data: []byte("none\n")}

	snapshot := collectMDArrayInventory(proc, sysfs, time.Now())
	if snapshot.Status != arrayInventoryAvailable || snapshot.ArrayCount != 1 {
		t.Fatalf("idle array with no active sync was marked incomplete: %s", formatMDArrayInventoryDiagnostic(snapshot))
	}
	array := snapshot.Arrays[0]
	if array.Health != arrayHealthHealthy || array.SyncAction != "idle" || array.SyncProgressPercent != nil {
		t.Fatalf("idle array exposed an invalid sync-progress observation: %+v", array)
	}
}

func TestCollectMDArrayInventoryAcceptsDelayedSyncProgress(t *testing.T) {
	proc := fstest.MapFS{
		"mdstat": {Data: []byte("Personalities : [raid1]\nmd0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\n      [>....................] resync = DELAYED\nunused devices: <none>\n")},
	}
	sysfs := fixtureMDArraySysfs("md0")
	sysfs["class/block/md0/md/array_state"] = &fstest.MapFile{Data: []byte("active\n")}
	sysfs["class/block/md0/md/sync_action"] = &fstest.MapFile{Data: []byte("resync\n")}
	sysfs["class/block/md0/md/sync_completed"] = &fstest.MapFile{Data: []byte("delayed\n")}

	snapshot := collectMDArrayInventory(proc, sysfs, time.Now())
	if snapshot.Status != arrayInventoryAvailable || snapshot.ArrayCount != 1 {
		t.Fatalf("delayed sync was marked incomplete: %s", formatMDArrayInventoryDiagnostic(snapshot))
	}
	array := snapshot.Arrays[0]
	if array.Health != arrayHealthSyncing || array.SyncAction != "resync" || array.SyncProgressPercent != nil {
		t.Fatalf("delayed sync observation was not preserved conservatively: %+v", array)
	}
}

func TestCollectMDArrayInventoryDisagreementStaysUnknown(t *testing.T) {
	const mdstat = "md0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\n"
	tests := []struct {
		name   string
		mdstat string
		mutate func(fstest.MapFS)
	}{
		{
			name: "level mismatch",
			mutate: func(sysfs fstest.MapFS) {
				sysfs["class/block/md0/md/level"] = &fstest.MapFile{Data: []byte("raid5\n")}
			},
		},
		{
			name: "degraded count mismatch",
			mutate: func(sysfs fstest.MapFS) {
				sysfs["class/block/md0/md/degraded"] = &fstest.MapFile{Data: []byte("1\n")}
			},
		},
		{
			name: "member mismatch",
			mutate: func(sysfs fstest.MapFS) {
				delete(sysfs, "class/block/md0/slaves/sdb2")
				sysfs["class/block/md0/slaves/sdc2"] = &fstest.MapFile{Mode: fs.ModeIrregular}
			},
		},
		{
			name: "sync action mismatch",
			mutate: func(sysfs fstest.MapFS) {
				sysfs["class/block/md0/md/sync_action"] = &fstest.MapFile{Data: []byte("idle\n")}
			},
			mdstat: "md0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks [2/2] [UU]\n      resync = 10.0% (100/1000) finish=1.0min speed=20K/sec\n",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			procData := mdstat
			if test.mdstat != "" {
				procData = test.mdstat
			}
			sysfs := fixtureMDArraySysfs("md0")
			test.mutate(sysfs)
			snapshot := collectMDArrayInventory(fstest.MapFS{"mdstat": {Data: []byte(procData)}}, sysfs, time.Now())
			if snapshot.Status != arrayInventoryPartial || len(snapshot.Arrays) != 1 || snapshot.Arrays[0].Health != arrayHealthUnknown {
				t.Fatalf("source disagreement produced a health conclusion: %+v", snapshot)
			}
		})
	}
}

func TestMDArrayInventoryDiagnosticIsBoundedAndInternal(t *testing.T) {
	const mdstat = "md0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\n"
	sysfs := fixtureMDArraySysfs("md0")
	delete(sysfs, "class/block/md0/md/sync_completed")
	snapshot := collectMDArrayInventory(fstest.MapFS{"mdstat": {Data: []byte(mdstat)}}, sysfs, time.Now())
	if snapshot.Status != arrayInventoryPartial || snapshot.ArrayCount != 1 || len(snapshot.Arrays) != 1 {
		t.Fatalf("fixture did not produce one incomplete MD observation: %+v", snapshot)
	}
	diagnostic := formatMDArrayInventoryDiagnostic(snapshot)
	for _, want := range []string{"status=partial", "array_count=1", "md0", "md-sync-progress-unavailable"} {
		if !strings.Contains(diagnostic, want) {
			t.Fatalf("diagnostic %q is missing %q", diagnostic, want)
		}
	}
	if len(diagnostic) > maxMDArrayDiagnosticBytes {
		t.Fatalf("MD diagnostic exceeded its bound: %d bytes", len(diagnostic))
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "diagnostic") || strings.Contains(string(encoded), "md-sysfs-attribute-unavailable") {
		t.Fatalf("internal failure detail escaped into the API response: %s", encoded)
	}
}

func TestMDArrayInventoryDiagnosticIdentifiesInvalidSysfsField(t *testing.T) {
	proc := fstest.MapFS{"mdstat": {Data: []byte("md0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\n")}}
	sysfs := fixtureMDArraySysfs("md0")
	sysfs["class/block/md0/md/sync_action"] = &fstest.MapFile{Data: []byte("resyncing\n")}
	snapshot := collectMDArrayInventory(proc, sysfs, time.Now())
	if snapshot.Status != arrayInventoryPartial {
		t.Fatalf("fixture did not preserve invalid sysfs state: %+v", snapshot)
	}
	if diagnostic := formatMDArrayInventoryDiagnostic(snapshot); !strings.Contains(diagnostic, "md-sync-action-invalid") {
		t.Fatalf("diagnostic did not identify invalid MD field: %q", diagnostic)
	}
}

func TestMDArrayInventoryDiagnosticIdentifiesProcSysfsDisagreement(t *testing.T) {
	proc := fstest.MapFS{"mdstat": {Data: []byte("md0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks super 1.2 [2/2] [UU]\n")}}
	sysfs := fixtureMDArraySysfs("md0")
	sysfs["class/block/md0/md/level"] = &fstest.MapFile{Data: []byte("raid5\n")}
	snapshot := collectMDArrayInventory(proc, sysfs, time.Now())
	if snapshot.Status != arrayInventoryPartial {
		t.Fatalf("fixture did not preserve the source disagreement: %+v", snapshot)
	}
	if diagnostic := formatMDArrayInventoryDiagnostic(snapshot); !strings.Contains(diagnostic, "mdstat-sysfs-disagreement") {
		t.Fatalf("diagnostic did not identify the MD source disagreement: %q", diagnostic)
	}
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

func TestClassifyFrozenMDArrayAsPaused(t *testing.T) {
	if health := classifyMDHealth("active", "frozen", "raid1", 2, 0, true); health != arrayHealthPaused {
		t.Fatalf("frozen sync action was classified as %q, want paused", health)
	}
}

func FuzzParseMDStat(f *testing.F) {
	f.Add("Personalities : [raid1]\nmd0 : active raid1 sda2[0] sdb2[1]\n      1024 blocks [2/2] [UU]\n")
	f.Add("md1 : active raid1 sda3[0] sdb3[1](F)\n      1024 blocks [2/1] [U_]\n      recovery = DELAYED\n")
	f.Add("md0 : inactive\n")
	f.Fuzz(func(t *testing.T, data string) {
		records, err := parseMDStat(data)
		if err != nil {
			return
		}
		if len(records) > maxMDArrayEntries {
			t.Fatal("parser returned too many arrays")
		}
		for _, record := range records {
			if !validMDName(record.name) || len(record.members) > maxMDMemberEntries {
				t.Fatal("parser returned an invalid or unbounded record")
			}
			if record.countsKnown && (record.expectedDevices == 0 || record.activeDevices > record.expectedDevices) {
				t.Fatal("parser returned inconsistent device counts")
			}
			if record.memberSlots != "" && record.countsKnown &&
				(uint32(len(record.memberSlots)) != record.expectedDevices ||
					uint32(strings.Count(record.memberSlots, "U")) != record.activeDevices) {
				t.Fatal("parser returned inconsistent member-slot counts")
			}
		}
	})
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
		devNumber := "9:0\n"
		if name == "md1" {
			devNumber = "9:1\n"
		}
		sysfs[base+"/dev"] = &fstest.MapFile{Data: []byte(devNumber)}
		sysfs[base+"/md"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
		arrayUUID := "11111111-2222-3333-4444-555555555555\n"
		if name == "md1" {
			arrayUUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee\n"
		}
		sysfs[base+"/md/uuid"] = &fstest.MapFile{Data: []byte(arrayUUID)}
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

func TestCanonicalMDArrayUUIDRejectsWhitespaceAndNormalizesCase(t *testing.T) {
	const lower = "11111111-2222-3333-4444-555555555555"
	for _, test := range []struct {
		value string
		want  string
		ok    bool
	}{
		{value: lower, want: lower, ok: true},
		{value: "11111111-2222-3333-4444-555555555555\n", want: lower, ok: true},
		{value: "11111111-2222-3333-4444-55555555555G", ok: false},
		{value: "  " + lower, ok: false},
		{value: lower + " \n", ok: false},
		{value: "00000000-0000-0000-0000-000000000000", ok: false},
	} {
		got, ok := canonicalMDArrayUUID(test.value)
		if got != test.want || ok != test.ok {
			t.Fatalf("canonicalMDArrayUUID(%q) = %q,%t, want %q,%t", test.value, got, ok, test.want, test.ok)
		}
	}
}
