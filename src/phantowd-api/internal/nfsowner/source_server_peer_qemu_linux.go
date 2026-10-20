//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package nfsowner

import "context"

// The ORIGINAL Owner gate covers the complete test mutation, before join/root/
// runtime gates. No point-in-time Observe is used as concurrency authority.
// The successful exit is not itself marked as supervised detection.
func (o *Owner) InjectSourceMountdExitFixtureQEMU(ctx context.Context) error {
	life, err := o.acquire(ctx)
	if err != nil {
		return err
	}
	defer life.unlock()
	if life.state == ReviewRequired {
		return ErrReviewRequired
	}
	if life.state != Running {
		return ErrState
	}
	b, ok := life.backend.(*sourceServerBackendQEMU)
	if !ok {
		return ErrInvalid
	}
	err = b.operate(ctx, false, func(source *SourceRuntimeQEMU, roots *exportRoots) error {
		if !source.accessServer || source.accessSettled {
			return ErrState
		}
		if err := source.verify(ctx, roots); err != nil {
			return err
		}
		return source.access.InjectServerMountdExitFixtureQEMU(ctx)
	})
	if err != nil {
		return life.review(err, true)
	}
	return nil
}
