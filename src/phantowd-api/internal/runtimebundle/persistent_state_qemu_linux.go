//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// Fixed disposable profile: private/state come from the caller's qualified
// synthetic ext4 root; all runtime directories remain on the original tmpfs.
// No product boot, filesystem admission or new state format is supplied.
func (p *Plan) NewPersistentNativeSambaRuntimeQEMU(ctx context.Context, code, configuration, state, persistent *os.File, lookup fileserviceplan.SambaEnrollmentLookup) (*NativeSambaRuntimeQEMU, error) {
	if persistent == nil {
		return nil, ErrInvalid
	}
	return p.newNativeSambaRuntimeWithStateQEMU(ctx, code, configuration, state, lookup, nil, persistent)
}
