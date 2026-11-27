// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const (
	rc0StorageApprovalFormat = "phantowd-rc0-storage-v1"
	rc0StorageApprovalLimit  = 32 << 10
	rc0StorageRole           = "storage.json"
	rc0VolumeRegistryRole    = "volume-registry"
	rc0StorageSourcesName    = "phantowd-data-sources"
	rc0StorageSourcesPath    = "/run/" + rc0StorageSourcesName
)

type rc0StorageApproval struct {
	Format           string              `json:"format"`
	RegistryRevision uint64              `json:"registry_revision"`
	Volumes          []rc0VolumeApproval `json:"volumes"`
	NFS              *rc0NFSApproval     `json:"nfs,omitempty"`
	SMB              *rc0ServiceEndpoint `json:"smb,omitempty"`
}

type rc0VolumeApproval struct {
	ID             shareconfig.VolumeID       `json:"id"`
	FilesystemUUID shareconfig.FilesystemUUID `json:"filesystem_uuid"`
	MountID        uint64                     `json:"mount_id"`
	RootInode      uint64                     `json:"root_inode"`
	DeviceMajor    uint32                     `json:"device_major"`
	DeviceMinor    *uint32                    `json:"device_minor"`
	ReadOnly       *bool                      `json:"read_only"`
	Disks          []rc0DiskApproval          `json:"disks"`
	Arrays         []rc0ArrayApproval         `json:"arrays"`
}

type rc0DiskApproval struct {
	Serial string `json:"serial_sha256"`
	WWN    string `json:"wwn_sha256"`
}

type rc0ArrayApproval struct {
	UUID  string `json:"uuid"`
	Level string `json:"level"`
}

var rc0StorageApprovalKeys = map[string]bool{
	"format": true, "registry_revision": true, "volumes": true, "id": true,
	"filesystem_uuid": true, "mount_id": true, "root_inode": true,
	"device_major": true, "device_minor": true, "read_only": true, "disks": true,
	"serial_sha256": true, "wwn_sha256": true, "arrays": true, "uuid": true, "level": true,
	"nfs": true, "smb": true, "address": true, "ingress_index": true,
}

func decodeRC0StorageApproval(data []byte, expected string) (rc0StorageApproval, error) {
	var approval rc0StorageApproval
	digest := sha256.Sum256(data)
	if expected != hex.EncodeToString(digest[:]) ||
		configjson.Decode(bytes.NewReader(data), &approval, rc0StorageApprovalLimit, 5, rc0StorageApprovalKeys) != nil ||
		approval.Format != rc0StorageApprovalFormat || approval.Volumes == nil || len(approval.Volumes) > shareconfig.MaxVolumes ||
		approval.NFS != nil && (len(approval.Volumes) == 0 || !approval.NFS.valid()) ||
		approval.SMB != nil && (len(approval.Volumes) == 0 || !approval.SMB.valid()) {
		return rc0StorageApproval{}, errRC0Review
	}
	claims := volumeregistry.Document{Format: volumeregistry.Format, SchemaVersion: volumeregistry.SchemaVersion,
		Revision: approval.RegistryRevision, Volumes: make([]shareconfig.Volume, 0, len(approval.Volumes))}
	for _, volume := range approval.Volumes {
		claims.Volumes = append(claims.Volumes, shareconfig.Volume{ID: volume.ID, FilesystemUUID: volume.FilesystemUUID})
		if _, err := volume.grant(); err != nil {
			return rc0StorageApproval{}, err
		}
	}
	if err := claims.Validate(); err != nil {
		return rc0StorageApproval{}, errRC0Review
	}
	return approval, nil
}

func (v rc0VolumeApproval) grant() (registeredStorageGrant, error) {
	if v.MountID == 0 || v.RootInode == 0 || v.DeviceMajor == 0 || v.DeviceMinor == nil || v.ReadOnly == nil ||
		len(v.Disks) == 0 || len(v.Disks) > 4 || v.Arrays == nil || len(v.Arrays) > 4 {
		return registeredStorageGrant{}, errRC0Review
	}
	g := registeredStorageGrant{mount: mountowner.LinuxVolumeGrant{
		VolumeID: string(v.ID), SourcePath: filepath.Join(rc0StorageSourcesPath, string(v.ID)),
		Expected: mountguard.Expected{MountID: v.MountID, RootInode: v.RootInode, DeviceMajor: v.DeviceMajor,
			DeviceMinor: *v.DeviceMinor, FilesystemType: unix.EXT4_SUPER_MAGIC, FilesystemUUID: string(v.FilesystemUUID),
			RequireWritable: !*v.ReadOnly},
	}}
	seenDisks := make(map[registeredDiskProof]bool, len(v.Disks))
	for _, disk := range v.Disks {
		var proof registeredDiskProof
		if !readRC0StorageHash(&proof.serial, disk.Serial) || !readRC0StorageHash(&proof.wwn, disk.WWN) ||
			proof == (registeredDiskProof{}) || seenDisks[proof] {
			return registeredStorageGrant{}, errRC0Review
		}
		seenDisks[proof] = true
		g.disks = append(g.disks, proof)
	}
	seenArrays := make(map[string]bool, len(v.Arrays))
	for _, array := range v.Arrays {
		canonical, valid := canonicalMDArrayUUID(array.UUID)
		if !valid || canonical != array.UUID || !validMDLevel(array.Level) || seenArrays[canonical] {
			return registeredStorageGrant{}, errRC0Review
		}
		seenArrays[canonical] = true
		g.arrays = append(g.arrays, registeredMDProof{uuid: canonical, level: array.Level})
	}
	return g, nil
}

func readRC0StorageHash(out *[32]byte, value string) bool {
	if value == "" {
		return true
	}
	if !validRC0SHA256(value) {
		return false
	}
	n, err := hex.Decode(out[:], []byte(value))
	return err == nil && n == len(out) && *out != [32]byte{}
}

// The publisher and consumer both read volatile, root-private bytes and tie
// them to the independently supplied boot plan.
func takeRC0StorageApproval(plan rc0BootPlan, descriptor int) (*rc0StorageApproval, []byte, error) {
	if plan.StorageSHA256 == "" {
		return nil, nil, nil
	}
	file, err := takeStartupFile(descriptor, unix.S_IFREG)
	if err != nil {
		return nil, nil, err
	}
	var fs unix.Statfs_t
	if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return nil, nil, errors.Join(errRC0Review, file.Close())
	}
	data, _, readErr := readPrivateStartupFile(file, 0, rc0StorageApprovalLimit)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return nil, nil, err
	}
	approval, err := decodeRC0StorageApproval(data, plan.StorageSHA256)
	if err != nil {
		return nil, nil, err
	}
	return &approval, data, nil
}

// The trusted platform has already mounted the sources beforehand. Boot opens
// only the fixed source roots and binds only the approved registered set.
func admitRC0BootStorage(ctx context.Context, state *os.File, approval *rc0StorageApproval) (_ *registeredStorage, result error) {
	if approval == nil {
		return nil, nil
	}
	registry, err := openRC0Role(state, rc0VolumeRegistryRole, unix.O_PATH|unix.O_DIRECTORY)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, registry.Close()) }()
	grants := make([]registeredStorageGrant, 0, len(approval.Volumes))
	if len(approval.Volumes) != 0 {
		if !safeRC0RunDirectory() {
			return nil, errRC0Review
		}
		run, err := os.Open("/run")
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, run.Close()) }()
		sources, err := openRC0BootDirectory(run, rc0StorageSourcesName)
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, sources.Close()) }()
		for _, volume := range approval.Volumes {
			g, err := volume.grant()
			if err != nil {
				return nil, err
			}
			fd, err := unix.Openat2(int(sources.Fd()), string(volume.ID), &unix.OpenHow{
				Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
				Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
			})
			if err != nil {
				return nil, err
			}
			source := os.NewFile(uintptr(fd), "rc0-approved-data-mount")
			defer func() { result = errors.Join(result, source.Close()) }()
			g.mount.Source = source
			grants = append(grants, g)
		}
	}
	return admitRegisteredStorage(ctx, registry, approval.RegistryRevision, grants)
}

// Withdrawal cannot discard the approval while any of its service mount
// targets could still hold a bind from a failed supervisor.
func requireWithdrawableRC0BootStorage(grant *os.File, plan rc0BootPlan) error {
	if plan.StorageSHA256 == "" {
		return nil
	}
	file, err := openRC0PrivateFile(grant, rc0StorageRole, rc0StorageApprovalLimit)
	if err != nil {
		return err
	}
	data, _, readErr := readPrivateStartupFile(file, 0, rc0StorageApprovalLimit)
	if err := errors.Join(readErr, file.Close()); err != nil {
		return err
	}
	approval, err := decodeRC0StorageApproval(data, plan.StorageSHA256)
	if err != nil {
		return err
	}
	return requireUnboundRC0Targets(approval.Volumes)
}

func requireUnboundRC0Targets(volumes []rc0VolumeApproval) error {
	for _, volume := range volumes {
		target := filepath.Join(shareconfig.VolumeMountRoot, string(volume.ID))
		fd, err := unix.Openat2(unix.AT_FDCWD, target, &unix.OpenHow{
			Flags: unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS,
		})
		if err != nil {
			return err
		}
		var stat unix.Statx_t
		statErr := unix.Statx(fd, "", unix.AT_EMPTY_PATH, unix.STATX_TYPE, &stat)
		if err := errors.Join(statErr, unix.Close(fd)); err != nil {
			return err
		}
		if stat.Attributes_mask&unix.STATX_ATTR_MOUNT_ROOT == 0 || stat.Attributes&unix.STATX_ATTR_MOUNT_ROOT != 0 {
			return errRC0Review
		}
	}
	return nil
}
