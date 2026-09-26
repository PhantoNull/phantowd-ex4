// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountguard

import (
	"sort"

	"golang.org/x/sys/unix"
)

const MaxMountedAnchors = 64

// MountedIdentity is an internal observation, not an activation capability.
// Raw UUIDs/paths must not be logged or exposed by a public diagnostics API.
type MountedIdentity struct {
	Anchor         string
	FilesystemUUID string
	MountID        uint64
	DeviceMajor    uint32
	DeviceMinor    uint32
}

// MountedInventory covers ONLY the explicitly supplied, already mounted
// ext-family anchors. Empty ConflictingUUIDs does not establish global
// uniqueness: unmounted/inaccessible/omitted disks were not discovered.
// It cannot select a volume, authorize mounting, or establish WD compatibility.
type MountedInventory struct {
	Mounts           []MountedIdentity
	ConflictingUUIDs []string
}

// ObserveMounted takes a bounded all-or-error snapshot. It opens no block
// devices and performs no mounting. Every anchor must be a non-symlink ext
// mount root; unsupported or inaccessible entries abort instead of becoming
// silently absent. Descriptors are retained and rechecked through collection,
// then closed. No lease/revocation guarantee survives this point-in-time call.
func ObserveMounted(anchors []string) (MountedInventory, error) {
	if len(anchors) == 0 || len(anchors) > MaxMountedAnchors {
		return MountedInventory{}, ErrUnsafe
	}
	seen := make(map[string]bool, len(anchors))
	for _, anchor := range anchors {
		if !validAbsolute(anchor) || seen[anchor] {
			return MountedInventory{}, ErrUnsafe
		}
		seen[anchor] = true
	}
	var roots []*Root
	defer func() {
		for _, root := range roots {
			root.Close()
		}
	}()
	observations := make([]MountedIdentity, 0, len(anchors))
	for _, anchor := range anchors {
		root, err := observeExtRoot(anchor)
		if err != nil {
			return MountedInventory{}, err
		}
		roots = append(roots, root)
		expected := root.expected
		observations = append(observations, MountedIdentity{Anchor: anchor, FilesystemUUID: expected.FilesystemUUID,
			MountID: expected.MountID, DeviceMajor: expected.DeviceMajor, DeviceMinor: expected.DeviceMinor})
	}
	for _, root := range roots {
		if err := root.Verify(); err != nil {
			return MountedInventory{}, err
		}
	}
	return groupMounted(observations)
}

func observeExtRoot(anchor string) (*Root, error) {
	fd, err := openPath(unix.AT_FDCWD, anchor, false)
	if err != nil {
		return nil, err
	}
	keep := false
	defer func() {
		if !keep {
			unix.Close(fd)
		}
	}()
	var st unix.Statx_t
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &st); err != nil {
		return nil, classify(err)
	}
	var filesystem unix.Statfs_t
	if err := unix.Fstatfs(fd, &filesystem); err != nil {
		return nil, classify(err)
	}
	// Only block-backed ext-family is in this observation profile. Magic does
	// not distinguish ext2/3/4 or qualify feature flags, health or migration.
	if uint32(filesystem.Type) != unix.EXT4_SUPER_MAGIC || st.Dev_major == 0 {
		return nil, ErrUnsupported
	}
	expected := Expected{MountID: st.Mnt_id, RootInode: st.Ino, DeviceMajor: st.Dev_major,
		DeviceMinor: st.Dev_minor, FilesystemType: uint32(filesystem.Type)}
	uuid, err := readRootUUID(fd, expected)
	if err != nil {
		return nil, err
	}
	expected.FilesystemUUID = uuid
	keep = true
	return &Root{fd: fd, path: anchor, expected: expected, ready: true}, nil
}

func groupMounted(mounts []MountedIdentity) (MountedInventory, error) {
	type device struct{ major, minor uint32 }
	byDevice := make(map[device]string)
	byUUID := make(map[string]map[device]bool)
	for _, mount := range mounts {
		key := device{mount.DeviceMajor, mount.DeviceMinor}
		if previous, ok := byDevice[key]; ok && previous != mount.FilesystemUUID {
			// Contradictory observations of one kernel device are not independent
			// volumes; discard the entire unstable/inconsistent snapshot.
			return MountedInventory{}, ErrMismatch
		}
		byDevice[key] = mount.FilesystemUUID
		if byUUID[mount.FilesystemUUID] == nil {
			byUUID[mount.FilesystemUUID] = make(map[device]bool)
		}
		byUUID[mount.FilesystemUUID][key] = true
	}
	result := MountedInventory{Mounts: append([]MountedIdentity{}, mounts...), ConflictingUUIDs: []string{}}
	for uuid, devices := range byUUID {
		if len(devices) > 1 {
			result.ConflictingUUIDs = append(result.ConflictingUUIDs, uuid)
		}
	}
	sort.Slice(result.Mounts, func(i, j int) bool { return result.Mounts[i].Anchor < result.Mounts[j].Anchor })
	sort.Strings(result.ConflictingUUIDs)
	return result, nil
}
