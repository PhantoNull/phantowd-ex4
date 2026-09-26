// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package volumeprobe supervises the read-only metadata helper. Its results
// are internal observations, never permissions to mount, format or activate.
package volumeprobe

import (
	"errors"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

var (
	ErrUnsafe   = errors.New("unsafe volume probe input")
	ErrBusy     = errors.New("volume probe already active")
	ErrProbe    = errors.New("volume probe failed")
	ErrResponse = errors.New("invalid volume probe response")
)

const maxOutput = 1024

// Result contains private storage identity. Do not log or expose it through
// public diagnostics. Unidentified is not empty, healthy or safe to provision.
type Result struct {
	Status         string
	SourceKind     string
	Filesystem     string
	FilesystemUUID string
}

type response struct {
	SchemaVersion          int     `json:"schema_version"`
	Status                 *string `json:"status"`
	SourceKind             *string `json:"source_kind"`
	Filesystem             *string `json:"filesystem"`
	FilesystemUUID         *string `json:"filesystem_uuid"`
	MountPerformed         *bool   `json:"mount_performed"`
	CompatibilityQualified *bool   `json:"compatibility_qualified"`
	ActivationAllowed      *bool   `json:"activation_allowed"`
}

func decode(input io.Reader) (Result, error) {
	var wire response
	fields := map[string]bool{"schema_version": true, "status": true, "source_kind": true,
		"filesystem": true, "filesystem_uuid": true, "mount_performed": true,
		"compatibility_qualified": true, "activation_allowed": true}
	if configjson.Decode(input, &wire, maxOutput, 2, fields) != nil || wire.SchemaVersion != 1 ||
		wire.Status == nil || wire.SourceKind == nil || wire.Filesystem == nil || wire.FilesystemUUID == nil ||
		wire.MountPerformed == nil || wire.CompatibilityQualified == nil || wire.ActivationAllowed == nil ||
		*wire.MountPerformed || *wire.CompatibilityQualified || *wire.ActivationAllowed {
		return Result{}, ErrResponse
	}
	result := Result{*wire.Status, *wire.SourceKind, *wire.Filesystem, *wire.FilesystemUUID}
	if result.SourceKind != "regular-image" && result.SourceKind != "block-device" {
		return Result{}, ErrResponse
	}
	switch result.Status {
	case "ext-metadata":
		if (result.Filesystem != "ext2" && result.Filesystem != "ext3" && result.Filesystem != "ext4") || !validUUID(result.FilesystemUUID) {
			return Result{}, ErrResponse
		}
	case "other-signature", "unusable-signature", "unidentified", "ambiguous":
		if result.Filesystem != "" || result.FilesystemUUID != "" {
			return Result{}, ErrResponse
		}
	default:
		return Result{}, ErrResponse
	}
	return result, nil
}

func validUUID(value string) bool {
	if len(value) != 36 {
		return false
	}
	nonzero := false
	for i, ch := range value {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if ch != '-' {
				return false
			}
			continue
		}
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
		nonzero = nonzero || ch != '0'
	}
	return nonzero
}
