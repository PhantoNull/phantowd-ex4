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
	if snapshot.SchemaVersion != 2 || snapshot.Scope != "kernel-sysfs-only" ||
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
	if disk.diskSequence != 41 || partition.diskSequence != 0 {
		t.Fatalf("kernel generation should be retained only for whole block nodes: disk=%d partition=%d", disk.diskSequence, partition.diskSequence)
	}
	if partition.Name != "sda1" || partition.Kind != "partition" || partition.PartitionNumber != 1 ||
		partition.Major != 8 || partition.Minor != 1 || partition.SizeBytes != (1<<30)-512 || !partition.ReadOnly {
		t.Fatalf("incorrect partition observation: %+v", partition)
	}
	if partition.ParentName != "sda" || partition.ParentMajor == nil || *partition.ParentMajor != disk.Major ||
		partition.ParentMinor == nil || *partition.ParentMinor != disk.Minor || partition.parentDiskSeq != disk.diskSequence {
		t.Fatalf("partition was not bound to its observed whole-disk parent: %+v", partition)
	}
	encoded, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{
		"fixture-secret", "PHANTOWD-QEMU-SERIAL-01", "500f000000000001", "fixture-fs-uuid-a",
		"fixture-partuuid-a", "disk_sequence", "parent_disk_seq",
		"lower_blocks", "holder_targets", "slave_targets",
	} {
		if strings.Contains(string(encoded), forbidden) {
			t.Fatalf("observation exposed identity material %q: %s", forbidden, encoded)
		}
	}
	var publicSnapshot struct {
		SchemaVersion int `json:"schema_version"`
		Observations  []struct {
			Name        string  `json:"name"`
			ParentName  string  `json:"parent_name"`
			ParentMajor *uint32 `json:"parent_major"`
			ParentMinor *uint32 `json:"parent_minor"`
		} `json:"observations"`
	}
	if err := json.Unmarshal(encoded, &publicSnapshot); err != nil {
		t.Fatal(err)
	}
	if publicSnapshot.SchemaVersion != 2 || len(publicSnapshot.Observations) != 2 ||
		publicSnapshot.Observations[0].Name != "sda" || publicSnapshot.Observations[0].ParentName != "" ||
		publicSnapshot.Observations[0].ParentMajor != nil || publicSnapshot.Observations[0].ParentMinor != nil {
		t.Fatalf("whole-disk JSON contains a partition parent or wrong schema: %+v", publicSnapshot)
	}
	publicPartition := publicSnapshot.Observations[1]
	if publicPartition.Name != "sda1" || publicPartition.ParentName != "sda" ||
		publicPartition.ParentMajor == nil || *publicPartition.ParentMajor != 8 ||
		publicPartition.ParentMinor == nil || *publicPartition.ParentMinor != 0 {
		t.Fatalf("schema-v2 JSON omitted the validated partition-parent tuple: %+v", publicPartition)
	}
}

func TestCollectStorageRejectsPartitionWithoutUniqueWholeDiskParent(t *testing.T) {
	sysfs := sysfsWithBlockLinks("orphan")
	snapshot, err := collectStorage(sysfs)
	if err == nil {
		t.Fatal("partition whose sysfs parent is absent from the whole-disk inventory was accepted")
	}
	if snapshot.DeviceCount != 0 || len(snapshot.Observations) != 0 {
		t.Fatalf("incomplete partition topology escaped in a partial snapshot: %+v", snapshot)
	}
}

func TestCollectStorageRejectsPartitionLinkChangedBeforeCompletion(t *testing.T) {
	sysfs := &changingBlockLinkFS{MapFS: fixtureSysfs()}
	snapshot, err := collectStorage(sysfs)
	if err == nil {
		t.Fatal("partition topology changed between collection passes without invalidating the snapshot")
	}
	if sysfs.reads != 2 {
		t.Fatalf("expected the partition link to be observed in both passes, got %d reads", sysfs.reads)
	}
	if snapshot.DeviceCount != 0 || len(snapshot.Observations) != 0 {
		t.Fatalf("a mixed partition topology escaped in a partial snapshot: %+v", snapshot)
	}
}

func TestObservedWholeDiskMountGuardDetectsVisibleStackedDeviceMount(t *testing.T) {
	sysfs := fixtureSysfs()
	addNonPartitionBlockNode(sysfs, "md0", 9, 0, "fixture-array-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	addNonPartitionBlockNode(sysfs, "dm-0", 253, 0, "fixture-mapper-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 3})
	addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "unrelated-disk-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 4})
	sysfs["devices/virtual/block/md0/diskseq"] = &fstest.MapFile{Data: []byte("52\n")}
	sysfs["devices/virtual/block/dm-0/diskseq"] = &fstest.MapFile{Data: []byte("53\n")}
	addSysfsBlockRelation(sysfs, "devices/virtual/block/sda/sda1", "holders", "md0", "../../../md0")
	addSysfsBlockRelation(sysfs, "devices/virtual/block/md0", "slaves", "sda1", "../../sda/sda1")
	addSysfsBlockRelation(sysfs, "devices/virtual/block/md0", "holders", "dm-0", "../../dm-0")
	addSysfsBlockRelation(sysfs, "devices/virtual/block/dm-0", "slaves", "md0", "../../md0")

	snapshot, err := collectStorage(sysfs)
	if err != nil {
		t.Fatal(err)
	}
	var disk *blockObservation
	for index := range snapshot.Observations {
		if snapshot.Observations[index].Name == "sda" {
			disk = &snapshot.Observations[index]
			break
		}
	}
	if disk == nil {
		t.Fatal("selected whole disk was not present in the complete inventory")
	}
	mounted, err := observedWholeDiskHasVisibleDependentMount(*disk, snapshot.Observations, []mountObservation{{DeviceMajor: 253, DeviceMinor: 0}})
	if err != nil {
		t.Fatal(err)
	}
	if !mounted {
		t.Fatal("mount on a device-mapper node above an MD holder was not attributed to its backing disk")
	}
	var unrelatedDisk *blockObservation
	for index := range snapshot.Observations {
		if snapshot.Observations[index].Name == "sdb" {
			unrelatedDisk = &snapshot.Observations[index]
			break
		}
	}
	if unrelatedDisk == nil {
		t.Fatal("unrelated whole disk was not present in the complete inventory")
	}
	mounted, err = observedWholeDiskHasVisibleDependentMount(*unrelatedDisk, snapshot.Observations, []mountObservation{{DeviceMajor: 253, DeviceMinor: 0}})
	if err != nil || mounted {
		t.Fatalf("mount on an unrelated stack was attributed to another disk: mounted=%v err=%v", mounted, err)
	}
}

func TestObservedWholeDiskMountGuardDetectsMultiMemberArrayMount(t *testing.T) {
	sysfs := fixtureSysfs()
	addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "fixture-array-member-b", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 4})
	addNonPartitionBlockNode(sysfs, "sdc", 8, 32, "unrelated-disk-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 5})
	addNonPartitionBlockNode(sysfs, "md0", 9, 0, "fixture-array-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 6})
	sysfs["devices/virtual/block/md0/diskseq"] = &fstest.MapFile{Data: []byte("90\n")}
	addSysfsBlockRelation(sysfs, "devices/virtual/block/sda/sda1", "holders", "md0", "../../../md0")
	addSysfsBlockRelation(sysfs, "devices/virtual/block/sdb", "holders", "md0", "../../md0")
	addSysfsBlockRelation(sysfs, "devices/virtual/block/md0", "slaves", "sda1", "../../sda/sda1")
	addSysfsBlockRelation(sysfs, "devices/virtual/block/md0", "slaves", "sdb", "../../sdb")

	snapshot, err := collectStorage(sysfs)
	if err != nil {
		t.Fatal(err)
	}
	nodes := make(map[string]blockObservation, len(snapshot.Observations))
	for _, observation := range snapshot.Observations {
		nodes[observation.Name] = observation
	}
	for _, member := range []string{"sda", "sdb"} {
		mounted, err := observedWholeDiskHasVisibleDependentMount(nodes[member], snapshot.Observations,
			[]mountObservation{{DeviceMajor: nodes["md0"].Major, DeviceMinor: nodes["md0"].Minor}})
		if err != nil || !mounted {
			t.Fatalf("MD mount was not attributed to backing member %s: mounted=%v err=%v", member, mounted, err)
		}
	}
	mounted, err := observedWholeDiskHasVisibleDependentMount(nodes["sdc"], snapshot.Observations,
		[]mountObservation{{DeviceMajor: nodes["md0"].Major, DeviceMinor: nodes["md0"].Minor}})
	if err != nil || mounted {
		t.Fatalf("multi-member MD mount was attributed to unrelated disk: mounted=%v err=%v", mounted, err)
	}
}

func TestCollectStorageRejectsNonReciprocalBlockRelations(t *testing.T) {
	sysfs := fixtureSysfs()
	addNonPartitionBlockNode(sysfs, "md0", 9, 0, "fixture-array-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	addSysfsBlockRelation(sysfs, "devices/virtual/block/sda/sda1", "holders", "md0", "../../../md0")

	snapshot, err := collectStorage(sysfs)
	if err == nil {
		t.Fatal("non-reciprocal sysfs holder/slave topology was accepted")
	}
	if snapshot.DeviceCount != 0 || len(snapshot.Observations) != 0 {
		t.Fatalf("incomplete stacked topology escaped as a partial inventory: %+v", snapshot)
	}
}

func TestCollectStorageRejectsEscapingBlockRelationLink(t *testing.T) {
	sysfs := fixtureSysfs()
	addSysfsBlockRelation(sysfs, "devices/virtual/block/sda", "holders", "sda", "../../../../../../etc/sda")
	snapshot, err := collectStorage(sysfs)
	if err == nil {
		t.Fatal("sysfs holder link escaping the devices tree was accepted")
	}
	if snapshot.DeviceCount != 0 || len(snapshot.Observations) != 0 {
		t.Fatalf("unsafe sysfs relation escaped in a partial inventory: %+v", snapshot)
	}
}

func TestCollectStorageRejectsBlockRelationsChangedBeforeCompletion(t *testing.T) {
	base := fixtureSysfs()
	addNonPartitionBlockNode(base, "md0", 9, 0, "fixture-array-serial", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	addSysfsBlockRelation(base, "devices/virtual/block/sda/sda1", "holders", "md0", "../../../md0")
	addSysfsBlockRelation(base, "devices/virtual/block/md0", "slaves", "sda1", "../../sda/sda1")
	sysfs := &changingBlockRelationFS{MapFS: base, path: "devices/virtual/block/sda/sda1/holders/md0"}

	snapshot, err := collectStorage(sysfs)
	if err == nil {
		t.Fatal("block holder relation changed during collection without invalidating the snapshot")
	}
	if sysfs.reads != 2 {
		t.Fatalf("expected the holder relation to be checked twice, got %d reads", sysfs.reads)
	}
	if snapshot.DeviceCount != 0 || len(snapshot.Observations) != 0 {
		t.Fatalf("a mixed block topology escaped in a partial inventory: %+v", snapshot)
	}
}

func TestReadSysfsBlockTargetRejectsOversizedLink(t *testing.T) {
	sysfs := fixtureSysfs()
	sysfs["class/block/sda1"] = &fstest.MapFile{
		Mode: fs.ModeSymlink,
		Data: []byte("../../devices/" + strings.Repeat("x", 4096) + "/sda1"),
	}
	if _, err := readSysfsBlockTarget(sysfs, "sda1"); err == nil {
		t.Fatal("oversized sysfs link target was accepted")
	}
}

func TestCollectStorageMarksCrossNodeVPDIdentityDuplicatesAmbiguous(t *testing.T) {
	naaA := []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 1}
	naaB := []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2}
	for _, test := range []struct {
		name       string
		serialA    string
		serialB    string
		wwnA       []byte
		wwnB       []byte
		wantSerial identityStatus
		wantWWN    identityStatus
	}{
		{
			name: "duplicate serial", serialA: "private-serial-shared", serialB: "private-serial-shared",
			wwnA: naaA, wwnB: naaB, wantSerial: identityAmbiguous, wantWWN: identityPresent,
		},
		{
			name: "duplicate WWN", serialA: "private-serial-a", serialB: "private-serial-b",
			wwnA: naaA, wwnB: naaA, wantSerial: identityPresent, wantWWN: identityAmbiguous,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sysfs := fixtureSysfs()
			addNonPartitionBlockNode(sysfs, "sdb", 8, 16, test.serialB, test.wwnB)
			// Replace sda's identifiers so each case controls both observed disks.
			sysfs["devices/virtual/block/sda/device/vpd_pg80"] = &fstest.MapFile{Data: makeVPDPage(0x80, []byte(test.serialA))}
			sysfs["devices/virtual/block/sda/device/vpd_pg83"] = &fstest.MapFile{Data: makeNAAPage(test.wwnA)}
			snapshot, err := collectStorage(sysfs)
			if err != nil {
				t.Fatal(err)
			}
			var nodeA, nodeB *blockObservation
			for index := range snapshot.Observations {
				observation := &snapshot.Observations[index]
				if observation.Name == "sda" {
					nodeA = observation
				}
				if observation.Name == "sdb" {
					nodeB = observation
				}
			}
			if nodeA == nil || nodeB == nil {
				t.Fatalf("fixture block nodes missing from snapshot: %+v", snapshot.Observations)
			}
			for _, node := range []*blockObservation{nodeA, nodeB} {
				if node.SerialStatus != test.wantSerial || node.WWNStatus != test.wantWWN {
					t.Fatalf("duplicate state was not applied to both block nodes: %+v", node)
				}
			}
			encoded, err := json.Marshal(snapshot)
			if err != nil {
				t.Fatal(err)
			}
			for _, secret := range []string{"private-serial-shared", "private-serial-a", "private-serial-b", "500f000000000001", "500f000000000002"} {
				if strings.Contains(string(encoded), secret) {
					t.Fatalf("duplicate-identity report leaked %q: %s", secret, encoded)
				}
			}
			if snapshot.StableIdentityAvailable {
				t.Fatal("redacted VPD collision checks must not claim stable identity is available")
			}
		})
	}
}

func TestCollectStorageRejectsBlockNodeReplacedDuringObservation(t *testing.T) {
	sysfs := &changingDiskSequenceFS{MapFS: fixtureSysfs(), changeAt: 2}
	if _, err := collectStorage(sysfs); err == nil {
		t.Fatal("block node whose kernel generation changed during observation was accepted")
	}
	if sysfs.reads != 2 {
		t.Fatalf("expected to pin and recheck one block-node generation, read diskseq %d times", sysfs.reads)
	}
}

func TestCollectStorageRejectsDuplicateBlockGenerations(t *testing.T) {
	sysfs := fixtureSysfs()
	addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "private-serial-b", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	sysfs["devices/virtual/block/sdb/diskseq"] = &fstest.MapFile{Data: []byte("41\n")}
	if _, err := collectStorage(sysfs); err == nil {
		t.Fatal("two whole-disk nodes with one kernel generation were accepted")
	}
}

func TestCollectStorageRequiresValidBlockGeneration(t *testing.T) {
	for _, test := range []struct {
		name  string
		value string
		omit  bool
	}{
		{name: "missing", omit: true},
		{name: "zero", value: "0\n"},
		{name: "signed", value: "+41\n"},
		{name: "non-decimal", value: "forty-one\n"},
		{name: "overflow", value: "18446744073709551616\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			sysfs := fixtureSysfs()
			if test.omit {
				delete(sysfs, "devices/virtual/block/sda/diskseq")
			} else {
				sysfs["devices/virtual/block/sda/diskseq"] = &fstest.MapFile{Data: []byte(test.value)}
			}
			if _, err := collectStorage(sysfs); err == nil {
				t.Fatal("missing or malformed block generation was accepted")
			}
		})
	}
}

func TestCollectStorageRechecksWholeInventoryBeforeReturning(t *testing.T) {
	sysfs := &lateChangingDiskSequenceFS{MapFS: fixtureSysfs()}
	if _, err := collectStorage(sysfs); err == nil {
		t.Fatal("block node replaced after its local check was accepted")
	}
	if sysfs.reads != 4 {
		t.Fatalf("expected generation reads across both complete observations, got %d", sysfs.reads)
	}
}

func TestCollectStorageRejectsPartitionMetadataChangedDuringObservation(t *testing.T) {
	sysfs := &changingStorageAttributeFS{
		MapFS: fixtureSysfs(),
		path:  "class/block/sda1/size",
		first: "2097151\n",
		later: "1048576\n",
	}
	if _, err := collectStorage(sysfs); err == nil {
		t.Fatal("partition metadata changed during observation without invalidating the snapshot")
	}
	if sysfs.reads != 2 {
		t.Fatalf("expected initial and consistency-check reads, got %d", sysfs.reads)
	}
}

func TestCollectStorageRejectsIdentityChangedBeforeDuplicateClassification(t *testing.T) {
	base := fixtureSysfs()
	addNonPartitionBlockNode(base, "sdb", 8, 16, "PHANTOWD-QEMU-SERIAL-01", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	sysfs := &changingStorageAttributeFS{
		MapFS: base,
		path:  "class/block/sdb/device/vpd_pg80",
		first: string(makeVPDPage(0x80, []byte("PHANTOWD-QEMU-SERIAL-01"))),
		later: string(makeVPDPage(0x80, []byte("replacement-serial"))),
	}
	snapshot, err := collectStorage(sysfs)
	if err == nil {
		t.Fatal("a VPD change after duplicate discovery was accepted as a consistent inventory")
	}
	if snapshot.DeviceCount != 0 || len(snapshot.Observations) != 0 {
		t.Fatalf("partial discovery escaped with an error: %+v", snapshot)
	}
	if sysfs.reads != 2 {
		t.Fatalf("expected initial and consistency-check VPD reads, got %d", sysfs.reads)
	}
}

func TestCollectStorageRejectsBlockNodesAddedDuringObservation(t *testing.T) {
	base := fixtureSysfs()
	addNonPartitionBlockNode(base, "sdb", 8, 16, "private-serial-b", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2})
	sysfs := &changingBlockInventoryFS{MapFS: base}
	if _, err := collectStorage(sysfs); err == nil {
		t.Fatal("block inventory changed during observation without invalidating the snapshot")
	}
	if sysfs.reads != 2 {
		t.Fatalf("expected initial and final inventory enumeration, got %d reads", sysfs.reads)
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
			delete(sysfs, "devices/virtual/block/sda/device/vpd_pg80")
			delete(sysfs, "devices/virtual/block/sda/device/vpd_pg83")
			if test.serialPage != nil {
				sysfs["devices/virtual/block/sda/device/vpd_pg80"] = &fstest.MapFile{Data: test.serialPage}
			}
			if test.wwnPage != nil {
				sysfs["devices/virtual/block/sda/device/vpd_pg83"] = &fstest.MapFile{Data: test.wwnPage}
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
			sysfs["devices/virtual/block/sda/"+test.field] = &fstest.MapFile{Data: []byte(test.value)}
			if _, err := collectStorage(sysfs); err == nil {
				t.Fatal("invalid sysfs observation accepted")
			}
		})
	}

	t.Run("partition number", func(t *testing.T) {
		sysfs := fixtureSysfs()
		sysfs["devices/virtual/block/sda/sda1/partition"] = &fstest.MapFile{Data: []byte("0\n")}
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
		"class":                                     {Mode: fs.ModeDir | 0o555},
		"class/block":                               {Mode: fs.ModeDir | 0o555},
		"class/block/sda":                           {Mode: fs.ModeSymlink, Data: []byte("../../devices/virtual/block/sda")},
		"class/block/sda1":                          {Mode: fs.ModeSymlink, Data: []byte("../../devices/virtual/block/sda/sda1")},
		"devices/virtual/block/sda/dev":             {Data: []byte("8:0\n")},
		"devices/virtual/block/sda/size":            {Data: []byte("2097152\n")},
		"devices/virtual/block/sda/ro":              {Data: []byte("0\n")},
		"devices/virtual/block/sda/removable":       {Data: []byte("0\n")},
		"devices/virtual/block/sda/diskseq":         {Data: []byte("41\n")},
		"devices/virtual/block/sda/holders":         {Mode: fs.ModeDir | 0o555},
		"devices/virtual/block/sda/slaves":          {Mode: fs.ModeDir | 0o555},
		"devices/virtual/block/sda/device":          {Mode: fs.ModeDir | 0o555},
		"devices/virtual/block/sda/device/vpd_pg80": {Data: makeVPDPage(0x80, []byte("PHANTOWD-QEMU-SERIAL-01"))},
		"devices/virtual/block/sda/device/vpd_pg83": {Data: makeVPDPage(0x83, []byte{0x01, 0x03, 0x00, 0x08, 0x50, 0x0f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})},
		"devices/virtual/block/sda/sda1/dev":        {Data: []byte("8:1\n")},
		"devices/virtual/block/sda/sda1/size":       {Data: []byte("2097151\n")},
		"devices/virtual/block/sda/sda1/ro":         {Data: []byte("1\n")},
		"devices/virtual/block/sda/sda1/removable":  {Data: []byte("0\n")},
		"devices/virtual/block/sda/sda1/partition":  {Data: []byte("1\n")},
		"devices/virtual/block/sda/sda1/holders":    {Mode: fs.ModeDir | 0o555},
	}
}

func addSysfsBlockRelation(sysfs fstest.MapFS, ownerTarget, relation, name, target string) {
	sysfs[ownerTarget+"/"+relation+"/"+name] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(target)}
}

func sysfsWithBlockLinks(partitionParent string) fstest.MapFS {
	sysfs := fixtureSysfs()
	if partitionParent != "sda" {
		const oldPrefix = "devices/virtual/block/sda/sda1"
		newPrefix := "devices/virtual/block/" + partitionParent + "/sda1"
		for name, file := range sysfs {
			if name == oldPrefix || strings.HasPrefix(name, oldPrefix+"/") {
				sysfs[newPrefix+strings.TrimPrefix(name, oldPrefix)] = file
				delete(sysfs, name)
			}
		}
		sysfs["class/block/sda1"] = &fstest.MapFile{
			Mode: fs.ModeSymlink,
			Data: []byte("../../devices/virtual/block/" + partitionParent + "/sda1"),
		}
	}
	return sysfs
}

func addNonPartitionBlockNode(sysfs fstest.MapFS, name string, major, minor uint32, serial string, wwn []byte) {
	target := "devices/virtual/block/" + name
	base := "class/block/" + name
	sysfs[base] = &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte("../../" + target)}
	sysfs[target+"/dev"] = &fstest.MapFile{Data: []byte(fmt.Sprintf("%d:%d\n", major, minor))}
	sysfs[target+"/size"] = &fstest.MapFile{Data: []byte("2097152\n")}
	sysfs[target+"/ro"] = &fstest.MapFile{Data: []byte("0\n")}
	sysfs[target+"/removable"] = &fstest.MapFile{Data: []byte("0\n")}
	sysfs[target+"/diskseq"] = &fstest.MapFile{Data: []byte(fmt.Sprintf("%d\n", minor+1))}
	sysfs[target+"/holders"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
	sysfs[target+"/slaves"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
	sysfs[target+"/device"] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
	sysfs[target+"/device/vpd_pg80"] = &fstest.MapFile{Data: makeVPDPage(0x80, []byte(serial))}
	sysfs[target+"/device/vpd_pg83"] = &fstest.MapFile{Data: makeNAAPage(wwn)}
}

type changingBlockLinkFS struct {
	fstest.MapFS
	reads int
}

type changingBlockRelationFS struct {
	fstest.MapFS
	path  string
	reads int
}

func (source *changingBlockRelationFS) ReadLink(name string) (string, error) {
	target, err := source.MapFS.ReadLink(name)
	if err != nil || name != source.path {
		return target, err
	}
	source.reads++
	if source.reads > 1 {
		return "../../../alternate/md0", nil
	}
	return target, nil
}

func (source *changingBlockLinkFS) ReadLink(name string) (string, error) {
	target, err := source.MapFS.ReadLink(name)
	if err != nil || name != "class/block/sda1" {
		return target, err
	}
	source.reads++
	if source.reads > 1 {
		return "../../devices/virtual/block/orphan/sda1", nil
	}
	return target, nil
}

type changingDiskSequenceFS struct {
	fstest.MapFS
	reads    int
	changeAt int
}

func (source *changingDiskSequenceFS) Open(name string) (fs.File, error) {
	if name == "class/block/sda/diskseq" {
		source.reads++
		sequence := "41\n"
		if source.reads >= source.changeAt {
			sequence = "42\n"
		}
		return (fstest.MapFS{name: &fstest.MapFile{Data: []byte(sequence)}}).Open(name)
	}
	return source.MapFS.Open(name)
}

type lateChangingDiskSequenceFS struct {
	fstest.MapFS
	reads int
}

func (source *lateChangingDiskSequenceFS) Open(name string) (fs.File, error) {
	if name == "class/block/sda/diskseq" {
		source.reads++
		sequence := "41\n"
		if source.reads >= 3 {
			sequence = "42\n"
		}
		return (fstest.MapFS{name: &fstest.MapFile{Data: []byte(sequence)}}).Open(name)
	}
	return source.MapFS.Open(name)
}

type changingBlockInventoryFS struct {
	fstest.MapFS
	reads int
}

func (source *changingBlockInventoryFS) ReadDir(name string) ([]fs.DirEntry, error) {
	entries, err := source.MapFS.ReadDir(name)
	if err != nil || name != "class/block" {
		return entries, err
	}
	source.reads++
	if source.reads > 1 {
		return entries, nil
	}
	filtered := make([]fs.DirEntry, 0, len(entries))
	for _, entry := range entries {
		if entry.Name() != "sdb" {
			filtered = append(filtered, entry)
		}
	}
	return filtered, nil
}

type changingStorageAttributeFS struct {
	fstest.MapFS
	path  string
	first string
	later string
	reads int
}

func (source *changingStorageAttributeFS) Open(name string) (fs.File, error) {
	if name == source.path {
		source.reads++
		value := source.first
		if source.reads > 1 {
			value = source.later
		}
		return (fstest.MapFS{name: &fstest.MapFile{Data: []byte(value)}}).Open(name)
	}
	return source.MapFS.Open(name)
}

func makeVPDPage(code byte, payload []byte) []byte {
	return append([]byte{0, code, byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func makeNAAPage(identifier []byte) []byte {
	payload := append([]byte{0x01, 0x03, 0x00, byte(len(identifier))}, identifier...)
	return makeVPDPage(0x83, payload)
}
