//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import "context"

// UnconsumedQEMU distinguishes a never-consumed capture from an executed and
// settled one. It neither starts/signals a child nor releases retained inputs.
// This fixture observation is not a product retry or recovery authorization.
func (c *CaptureOwner) UnconsumedQEMU(ctx context.Context) (bool, error) {
	if err := c.enter(ctx); err != nil {
		return false, err
	}
	defer func() { <-c.gate }()
	if c.closed || c.closeFailed {
		return false, ErrUnavailable
	}
	return !c.consumed && c.current == nil, nil
}
