// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package iscsipreview projects validated coherent desired policy for review.
// It grants no storage, credential, listener, session or activation authority.
package iscsipreview

import (
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

const (
	Format         = "phantowd-desired-iscsi-preview"
	SchemaVersion  = 2
	MaxOutputBytes = 256 << 10
)

var ErrInvalid = errors.New("invalid desired iSCSI preview")

// Preview is caller-owned display data, not a retained policy claim or token.
// Revision/capacities are decimal strings to preserve uint64 precision in a
// browser. Counts, block sizes and LUN numbers fit exact JavaScript integers.
type Preview struct {
	Format               string    `json:"format"`
	SchemaVersion        int       `json:"schema_version"`
	Scope                string    `json:"scope"`
	Revision             string    `json:"revision"`
	StorageValidated     bool      `json:"storage_validated"`
	CredentialsValidated bool      `json:"credentials_validated"`
	RuntimeValidated     bool      `json:"runtime_validated"`
	ActivationAvailable  bool      `json:"activation_available"`
	SMBDefinitions       int       `json:"smb_definitions"`
	NFSDefinitions       int       `json:"nfs_definitions"`
	Backings             []Backing `json:"backings"`
	Targets              []Target  `json:"targets"`
	Limitations          []string  `json:"limitations"`
}

type Backing struct {
	ID                  string `json:"id"`
	VolumeID            string `json:"volume_id"`
	RelativePath        string `json:"relative_path"`
	CapacityBytes       string `json:"capacity_bytes"`
	BlockSize           uint16 `json:"block_size"`
	Allocation          string `json:"allocation"`
	SMBPathOverlapCount int    `json:"smb_path_overlap_count"`
	NFSPathOverlapCount int    `json:"nfs_path_overlap_count"`
}

type Target struct {
	ID           string      `json:"id"`
	Name         string      `json:"name"`
	DesiredState string      `json:"desired_state"`
	LUNs         []LUN       `json:"luns"`
	Initiators   []Initiator `json:"initiators"`
}

type LUN struct {
	ID        string `json:"id"`
	Number    uint16 `json:"number"`
	BackingID string `json:"backing_id"`
	Access    string `json:"access"`
}

// Initiator deliberately contains no credential username or SecretRef.
// Authentication describes the desired mode, not verified authentication.
type Initiator struct {
	Name                  string  `json:"name"`
	DesiredAuthentication string  `json:"desired_authentication"`
	Grants                []Grant `json:"grants"`
}

type Grant struct {
	LUNID  string `json:"lun_id"`
	Access string `json:"access"`
}

// Build first validates the whole coherent SMB/NFS/iSCSI document. It does not
// select a legacy store, resolve VolumeIDs/SecretRefs, inspect a backing object,
// evaluate effective access or admit a service. Input remains caller-owned and
// must not be changed concurrently. Every failure returns zero display data.
func Build(config naspolicy.Config) (Preview, error) {
	if config.Validate() != nil {
		return Preview{}, ErrInvalid
	}
	p := Preview{
		Format: Format, SchemaVersion: SchemaVersion, Scope: "desired-policy-only",
		Revision:       strconv.FormatUint(config.Revision, 10),
		SMBDefinitions: len(config.FileServices.Shares.Shares),
		NFSDefinitions: len(config.FileServices.NFS.Exports),
		Backings:       make([]Backing, 0, len(config.ISCSI.Backings)),
		Targets:        make([]Target, 0, len(config.ISCSI.Targets)),
		Limitations: []string{
			"Desired definitions only; enabled is not evidence of a running target.",
			"Configured same-volume path overlaps are advisory only, including read-only shares and disabled targets. Zero does not exclude filesystem aliases, external shares or actual use.",
			"Storage identity, backing size/allocation, free space and cross-protocol/global use are not validated.",
			"Credentials, effective access, initiator sessions and network reachability are not validated.",
			"CHAP does not encrypt data traffic. No service is saved, started or changed by this preview.",
		},
	}
	for _, b := range config.ISCSI.Backings {
		row := Backing{ID: string(b.ID), VolumeID: string(b.VolumeID),
			RelativePath: b.RelativePath, CapacityBytes: strconv.FormatUint(b.CapacityBytes, 10),
			BlockSize: b.BlockSize, Allocation: b.Allocation}
		for _, share := range config.FileServices.Shares.Shares {
			if share.VolumeID == b.VolumeID && configuredPathOverlap(share.RelativePath, b.RelativePath) {
				row.SMBPathOverlapCount++
			}
		}
		for _, export := range config.FileServices.NFS.Exports {
			if export.VolumeID == b.VolumeID && configuredPathOverlap(export.RelativePath, b.RelativePath) {
				row.NFSPathOverlapCount++
			}
		}
		p.Backings = append(p.Backings, row)
	}
	for _, target := range config.ISCSI.Targets {
		t := Target{ID: string(target.ID), Name: target.Name, DesiredState: target.State,
			LUNs: make([]LUN, 0, len(target.LUNs)), Initiators: make([]Initiator, 0, len(target.Initiators))}
		for _, lun := range target.LUNs {
			t.LUNs = append(t.LUNs, LUN{ID: string(lun.ID), Number: lun.Number, BackingID: string(lun.BackingID), Access: lun.Access})
		}
		for _, peer := range target.Initiators {
			i := Initiator{Name: peer.Name, DesiredAuthentication: peer.Authentication.Mode, Grants: make([]Grant, 0, len(peer.Grants))}
			for _, grant := range peer.Grants {
				i.Grants = append(i.Grants, Grant{LUNID: string(grant.LUNID), Access: grant.Access})
			}
			t.Initiators = append(t.Initiators, i)
		}
		p.Targets = append(p.Targets, t)
	}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > MaxOutputBytes {
		return Preview{}, ErrInvalid
	}
	return p, nil
}

// Only validated canonical volume-relative paths enter this comparison. Never
// normalize/case-fold, resolve filesystem objects or treat a negative as safety.
func configuredPathOverlap(a, b string) bool {
	return a == "." || b == "." || a == b || strings.HasPrefix(a, b+"/") || strings.HasPrefix(b, a+"/")
}
