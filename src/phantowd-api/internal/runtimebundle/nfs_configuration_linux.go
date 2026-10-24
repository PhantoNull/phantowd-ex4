//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"crypto/sha256"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// Expectations must be independently derived from the same immutable candidate,
// never from the configuration tree under inspection. No state/activation grant.
func nfsConfigurationPlan(candidate fileserviceplan.NFSv3Candidate) (bool, *configurationPlan, error) {
	enabled, documents, err := NFSv3Documents(candidate)
	if err != nil || !enabled {
		return enabled, nil, err
	}
	var files []File
	for name, contents := range documents {
		mode := uint32(0600)
		if name == "etc/netconfig" {
			mode = 0644
		}
		files = append(files, File{Path: name, Size: int64(len(contents)), SHA256: sha256.Sum256([]byte(contents)), Mode: mode})
	}
	plan, err := newConfigurationPlan(files)
	if err != nil {
		return false, nil, err
	}
	return true, plan, nil
}
