//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
)

type ExportRootsQEMU = ExportRoots

func NewExportRootsQEMU(ctx context.Context, candidate fileserviceplan.NFSv3Candidate, lease *mountowner.MountedVolumeSetLease) (*ExportRootsQEMU, error) {
	return NewExportRoots(ctx, candidate, lease)
}
