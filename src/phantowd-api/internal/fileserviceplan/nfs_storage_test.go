// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"reflect"
	"slices"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestNFSCandidateStorageComparisonCoversTheCompleteRoster(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	other := config.Shares.Volumes[0]
	other.ID, other.FilesystemUUID = "other", "66666666-7777-8888-9999-aaaaaaaaaaaa"
	config.Shares.Volumes = append(config.Shares.Volumes, other)
	extra := storage.Volumes[0]
	extra.VolumeID, extra.FilesystemUUID, extra.MountPath = other.ID, other.FilesystemUUID, shareconfig.VolumeMountRoot+"/other"
	extra.MountID++
	extra.DeviceMinor++
	storage.Volumes = append(storage.Volumes, extra)
	storage.OwnerFingerprint[0] = 1
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	matcher, ok := any(candidate).(interface{ FreshAgainstStorage(StorageSnapshot) bool })
	if !ok {
		t.Fatal("NFS candidate lacks original-storage comparison")
	}
	before := slices.Clone(storage.Volumes)
	if !matcher.FreshAgainstStorage(storage) {
		t.Fatal("unchanged complete storage refused")
	}
	for _, tc := range []struct {
		name   string
		change func(*StorageSnapshot)
	}{
		{"incomplete", func(s *StorageSnapshot) { s.Complete = false }},
		{"generation", func(s *StorageSnapshot) { s.Generation++ }},
		{"owner", func(s *StorageSnapshot) { s.OwnerFingerprint[0]++ }},
		{"missing", func(s *StorageSnapshot) { s.Volumes = nil }},
		{"empty", func(s *StorageSnapshot) { s.Volumes = []ObservedVolume{} }},
		{"oversize", func(s *StorageSnapshot) { s.Volumes = make([]ObservedVolume, MaxObservedVolumes+1) }},
		{"logical-id", func(s *StorageSnapshot) { s.Volumes[0].VolumeID = "changed" }},
		{"filesystem", func(s *StorageSnapshot) { s.Volumes[0].FilesystemUUID = other.FilesystemUUID }},
		{"anchor", func(s *StorageSnapshot) { s.Volumes[0].MountPath += "-changed" }},
		{"compatibility", func(s *StorageSnapshot) { s.Volumes[0].Compatibility = "unknown" }},
		{"mount", func(s *StorageSnapshot) { s.Volumes[0].MountID++ }},
		{"major", func(s *StorageSnapshot) { s.Volumes[0].DeviceMajor++ }},
		{"minor", func(s *StorageSnapshot) { s.Volumes[0].DeviceMinor++ }},
		{"readonly", func(s *StorageSnapshot) { s.Volumes[0].ReadOnly = !s.Volumes[0].ReadOnly }},
		{"unselected-member", func(s *StorageSnapshot) { s.Volumes[1].MountID++ }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			changed := storage
			changed.Volumes = slices.Clone(storage.Volumes)
			tc.change(&changed)
			if matcher.FreshAgainstStorage(changed) {
				t.Fatal("changed or incomplete storage accepted")
			}
		})
	}
	reordered := storage
	reordered.Volumes = slices.Clone(storage.Volumes)
	slices.Reverse(reordered.Volumes)
	if !matcher.FreshAgainstStorage(reordered) || !reflect.DeepEqual(storage.Volumes, before) {
		t.Fatal("comparison depended on order or mutated the input")
	}
	zero := any(NFSv3Candidate{}).(interface{ FreshAgainstStorage(StorageSnapshot) bool })
	if zero.FreshAgainstStorage(storage) {
		t.Fatal("zero candidate matched storage")
	}
}
