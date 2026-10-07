//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Candidate/parser qualification only. This does not attach a share clone,
// authenticate a client or grant file access through the candidate.
func validateQEMUIsolatedSambaPlan(plan fileserviceplan.Plan) error {
	sections, roots, err := plan.SambaShareCandidates()
	if err != nil || len(roots) != 1 || roots[0].ID != "books" || roots[0].VolumeID != qemuPlannerVolumeID ||
		roots[0].RelativePath != "books" || roots[0].ReadOnly ||
		!strings.Contains(sections, "path = /shares/books\n") ||
		!strings.Contains(sections, "write list = alice\n") || strings.Contains(sections, shareconfig.VolumeMountRoot) {
		return errors.New("isolated QEMU candidate lost its declared root/grant binding")
	}
	return validateQEMUIsolatedSambaWithTestparm(sections)
}
