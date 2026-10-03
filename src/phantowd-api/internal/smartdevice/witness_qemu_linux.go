//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smartdevice

import (
	"context"
	"errors"
)

// VerifyQEMUStickyReview changes the expected tuple only inside the QEMU test
// build, not the kernel/device. Real Check must refuse; restoring that tuple
// cannot clear review. This is not a physical hot-unplug/replacement test.
func VerifyQEMUStickyReview(ctx context.Context, w *Witness) error {
	if w == nil || w.Check(ctx) != nil {
		return ErrUnsafe
	}
	expected := w.expected
	w.expected.DiskSequence ^= 1
	refused := w.Check(ctx)
	w.expected = expected
	if !errors.Is(refused, ErrUnsafe) || !errors.Is(w.Check(ctx), ErrReview) {
		return ErrUnsafe
	}
	return nil
}
