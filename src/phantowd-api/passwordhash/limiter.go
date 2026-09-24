// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package passwordhash

import (
	"context"
	"errors"
)

var (
	kdfSlot       = make(chan struct{}, 1)
	errNilContext = errors.New("password KDF context is nil")
)

// withKDFSlot serializes all package KDF operations process-wide. A caller
// waiting for the slot can cancel without starting KDF work. Once started, the
// synchronous Argon2 implementation is not interruptible.
func withKDFSlot(ctx context.Context, work func() error) error {
	if ctx == nil {
		return errNilContext
	}
	if work == nil {
		return errors.New("password KDF work is nil")
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
	}
	select {
	case kdfSlot <- struct{}{}:
		defer func() { <-kdfSlot }()
		if err := ctx.Err(); err != nil {
			return err
		}
		return work()
	case <-ctx.Done():
		return ctx.Err()
	}
}
