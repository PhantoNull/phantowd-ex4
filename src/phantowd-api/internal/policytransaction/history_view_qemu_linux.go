//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

// Fixed typed views of the SAME disposable writer, not per-operation backend
// injection. Build from its owned base and hold its original lock through the
// existing intent -> policy -> receipt transaction. Product/recovery/HTTP and
// existing-state admission are deliberately not introduced by this bridge.
func (w *writer) executeFileServicesHistory(ctx context.Context, expected uint64, next fileservice.Config) (localOutcome, error) {
	if w == nil || w.self != w || ctx == nil {
		return localOutcome{}, ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	base, err := w.historyViewBaseLocked(ctx, expected)
	if err != nil {
		return localOutcome{}, err
	}
	candidate, err := naspolicy.ReplaceFileServices(base, next)
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	return w.executeHistoryLocked(ctx, candidate)
}

func (w *writer) executeISCSIHistory(ctx context.Context, expected uint64, next iscsipolicy.Policy) (localOutcome, error) {
	if w == nil || w.self != w || ctx == nil {
		return localOutcome{}, ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	base, err := w.historyViewBaseLocked(ctx, expected)
	if err != nil {
		return localOutcome{}, err
	}
	candidate, err := naspolicy.ReplaceISCSI(base, next)
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	return w.executeHistoryLocked(ctx, candidate)
}

func (w *writer) historyViewBaseLocked(ctx context.Context, expected uint64) (naspolicy.Config, error) {
	if err := w.historyReadyLocked(ctx); err != nil {
		return naspolicy.Config{}, err
	}
	if w.guard(ctx) != nil || w.history.check() != nil {
		return naspolicy.Config{}, w.poison(ctx)
	}
	base, err := naspolicy.Decode(bytes.NewReader(w.base))
	if err != nil {
		return naspolicy.Config{}, w.poison(ctx)
	}
	if base.Revision != expected {
		return naspolicy.Config{}, ErrInvalid
	}
	// executeHistoryLocked independently rechecks exact current bytes, anchored
	// history and the same retained guards before any effect. This cached base is
	// not an independent current-policy observation or a caller-provided witness.
	return base, nil
}
