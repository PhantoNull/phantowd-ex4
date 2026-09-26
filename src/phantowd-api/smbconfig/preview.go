// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package smbconfig previews Samba share sections without filesystem access,
// account provisioning or service activation.
package smbconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"path"
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const VolumeRoot = shareconfig.VolumeMountRoot

// Preview describes desired SMB policy, not effective filesystem access.
// Neither this object nor successful testparm validation authorizes activation.
type Preview struct {
	SchemaVersion int                 `json:"schema_version"`
	Revision      uint64              `json:"revision"`
	Volumes       []VolumeRequirement `json:"required_volumes"`
	Shares        []SharePreview      `json:"shares"`
	Sections      string              `json:"samba_share_sections"`
}

// The activation layer must prove the exact, unique filesystem identity is
// mounted here, retain that binding and prevent fallback into the system disk.
type VolumeRequirement struct {
	VolumeID       string `json:"volume_id"`
	FilesystemUUID string `json:"filesystem_uuid"`
	MountPath      string `json:"mount_path"`
}

type SharePreview struct {
	ID        string   `json:"id"`
	Name      string   `json:"name"`
	VolumeID  string   `json:"volume_id"`
	Path      string   `json:"path"`
	ReadOnly  []string `json:"read_only_users"`
	ReadWrite []string `json:"read_write_users"`
}

// Build is deterministic for semantically equivalent collection orderings.
// It refuses unsafe Samba interpolation and overlapping paths. Mount/ACL and
// symlink checks cannot be established lexically and remain activation gates.
func Build(config shareconfig.Config) (Preview, error) {
	if err := config.Validate(); err != nil {
		return Preview{}, errors.New("invalid desired share policy")
	}
	encoded, err := json.Marshal(config)
	if err != nil || len(encoded) > shareconfig.MaxInputBytes {
		return Preview{}, errors.New("share policy exceeds preview limit")
	}
	preview := Preview{SchemaVersion: 1, Revision: config.Revision,
		Volumes: []VolumeRequirement{}, Shares: []SharePreview{}}
	volumes := make(map[string]VolumeRequirement, len(config.Volumes))
	for _, volume := range config.Volumes {
		volumes[volume.ID] = VolumeRequirement{volume.ID, volume.FilesystemUUID, path.Join(VolumeRoot, volume.FilesystemUUID)}
	}
	names := make(map[string]string, len(config.Users))
	for _, user := range config.Users {
		names[user.ID] = user.Name
	}
	used := make(map[string]bool)
	for i, share := range config.Shares {
		if unsafeValue(share.Name) || unsafeValue(share.RelativePath) {
			return Preview{}, fmt.Errorf("share %d cannot be represented safely in Samba", i)
		}
		for _, part := range strings.Split(share.RelativePath, "/") {
			if strings.TrimSpace(part) != part {
				return Preview{}, fmt.Errorf("share %d has ambiguous path whitespace", i)
			}
		}
		volume := volumes[share.VolumeID]
		resolved := path.Join(volume.MountPath, share.RelativePath)
		for _, other := range preview.Shares {
			if other.VolumeID == share.VolumeID && overlaps(other.Path, resolved) {
				return Preview{}, errors.New("overlapping share paths require an explicit ACL policy")
			}
		}
		item := SharePreview{ID: share.ID, Name: share.Name, VolumeID: share.VolumeID, Path: resolved,
			ReadOnly: []string{}, ReadWrite: []string{}}
		for _, grant := range share.Grants {
			if grant.Access == "rw" {
				item.ReadWrite = append(item.ReadWrite, names[grant.UserID])
			} else {
				item.ReadOnly = append(item.ReadOnly, names[grant.UserID])
			}
		}
		slices.Sort(item.ReadOnly)
		slices.Sort(item.ReadWrite)
		preview.Shares = append(preview.Shares, item)
		used[share.VolumeID] = true
	}
	for id := range used {
		preview.Volumes = append(preview.Volumes, volumes[id])
	}
	slices.SortFunc(preview.Volumes, func(a, b VolumeRequirement) int { return strings.Compare(a.VolumeID, b.VolumeID) })
	slices.SortFunc(preview.Shares, func(a, b SharePreview) int { return strings.Compare(a.ID, b.ID) })
	var output strings.Builder
	output.WriteString("# PhantoWD candidate share sections; not an activation authorization.\n")
	output.WriteString("# Verify filesystem identity, mount containment, accounts and POSIX ACLs first.\n")
	for _, share := range preview.Shares {
		allowed := append(slices.Clone(share.ReadOnly), share.ReadWrite...)
		slices.Sort(allowed)
		fmt.Fprintf(&output, "\n[%s]\n    path = %s\n", share.Name, share.Path)
		output.WriteString("    guest ok = no\n    guest only = no\n    read only = yes\n    browseable = yes\n")
		fmt.Fprintf(&output, "    valid users = %s\n", strings.Join(allowed, " "))
		fmt.Fprintf(&output, "    read list = %s\n", strings.Join(share.ReadOnly, " "))
		fmt.Fprintf(&output, "    write list = %s\n", strings.Join(share.ReadWrite, " "))
		output.WriteString("    wide links = no\n    follow symlinks = no\n    create mask = 0660\n    directory mask = 0770\n")
	}
	preview.Sections = output.String()
	return preview, nil
}

func unsafeValue(s string) bool {
	// Percent expressions expand in Samba. Quotes/comments/delimiters are
	// rejected rather than relying on context-dependent escaping rules.
	return strings.ContainsAny(s, "%\"#;=[]")
}

func overlaps(a, b string) bool {
	return a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
