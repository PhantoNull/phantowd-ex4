// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountguard

import (
	"errors"
	"reflect"
	"testing"
)

func TestMountedGroups(t *testing.T) {
	uuid := "11111111-2222-3333-4444-555555555555"
	a := MountedIdentity{Anchor: "/a", FilesystemUUID: uuid, MountID: 1, DeviceMajor: 8, DeviceMinor: 16}
	b := a
	b.Anchor, b.MountID = "/b", 2
	for _, alias := range []bool{true, false} {
		if !alias {
			b.DeviceMinor = 32
		}
		result, err := groupMounted([]MountedIdentity{b, a})
		if err != nil || len(result.Mounts) != 2 || result.Mounts[0] != a || (len(result.ConflictingUUIDs) == 0) != alias {
			t.Fatal("alias versus cloned logical device", result, err)
		}
		reversed, err := groupMounted([]MountedIdentity{a, b})
		if err != nil || !reflect.DeepEqual(result, reversed) {
			t.Fatal("enumeration order changed result")
		}
	}
	b.DeviceMinor = a.DeviceMinor
	b.FilesystemUUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
	if result, err := groupMounted([]MountedIdentity{a, b}); !errors.Is(err, ErrMismatch) || result.Mounts != nil {
		t.Fatal("inconsistent device identity yielded a partial result", result, err)
	}
	b.DeviceMinor = 32
	if result, err := groupMounted([]MountedIdentity{a, b}); err != nil || len(result.ConflictingUUIDs) != 0 {
		t.Fatal("different device and UUID is not a clone", result, err)
	}
}

func TestMountedInventoryRefusals(t *testing.T) {
	for _, anchors := range [][]string{nil, {}, {"relative"}, {"/"}, {"/a", "/a"}, make([]string, MaxMountedAnchors+1)} {
		if result, err := ObserveMounted(anchors); !errors.Is(err, ErrUnsafe) || result.Mounts != nil {
			t.Fatal("invalid request produced inventory", err)
		}
	}
	for _, anchors := range [][]string{{"/proc"}, {t.TempDir()}, {"/phantowd-no-such-mount"}} {
		if result, err := ObserveMounted(anchors); err == nil || result.Mounts != nil {
			t.Fatal("unsupported/missing/non-root directory produced inventory", result, err)
		}
	}
}
