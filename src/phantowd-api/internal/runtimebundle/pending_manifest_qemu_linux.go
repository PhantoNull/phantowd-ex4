//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
)

// Independent expected build metadata for disposable fixtures ONLY. These
// unsigned documents grant no execution, storage or product update authority.
type PendingExpectedFileQEMU struct {
	Path, SHA256 string
	Size         int64
	Mode         uint32
}

type PendingExpectedManifestQEMU struct {
	Format         string
	RootFiles      []PendingExpectedFileQEMU
	RootAliases    []Alias
	BootstrapFiles []PendingExpectedFileQEMU
}

func DecodePendingExpectedQEMU(data []byte) (PendingExpectedManifestQEMU, error) {
	var manifest PendingExpectedManifestQEMU
	if len(data) > 128<<10 {
		return manifest, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&manifest) != nil || decoder.Decode(new(any)) != io.EOF || manifest.Format != "phantowd-qemu-pending-client-inputs-v1" {
		return PendingExpectedManifestQEMU{}, ErrInvalid
	}
	return manifest, nil
}

func PendingExpectedPlanQEMU(files []PendingExpectedFileQEMU, aliases []Alias) (*Plan, error) {
	var result []File
	for _, file := range files {
		decoded, err := hex.DecodeString(file.SHA256)
		if err != nil || len(decoded) != 32 {
			return nil, ErrInvalid
		}
		var digest [32]byte
		copy(digest[:], decoded)
		result = append(result, File{Path: file.Path, SHA256: digest, Size: file.Size, Mode: file.Mode})
	}
	return NewPlan(result, aliases)
}

func readPendingExpectedQEMU() (*Plan, *Plan, error) {
	if err := sambaCodeFixtureGuard(); err != nil {
		return nil, nil, err
	}
	file, err := os.Open("/usr/lib/phantowd/qemu-pending-client-inputs.json")
	if err != nil {
		return nil, nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	closeErr := file.Close()
	if readErr != nil || closeErr != nil {
		return nil, nil, errors.Join(readErr, closeErr)
	}
	manifest, err := DecodePendingExpectedQEMU(data)
	if err != nil {
		return nil, nil, err
	}
	client, err := PendingExpectedPlanQEMU(manifest.RootFiles, manifest.RootAliases)
	if err != nil {
		return nil, nil, err
	}
	bootstrap, err := PendingExpectedPlanQEMU(manifest.BootstrapFiles, nil)
	return client, bootstrap, err
}
