//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// sealSession serializes one declaration with the SAME original writer root,
// policy/history locks and owned current bytes. No external consumers exist in
// this fresh QEMU profile. This is not clean shutdown or product boot admission.
// Close never calls this method automatically.
func (w *writer) sealSession(ctx context.Context) error {
	if w == nil || w.self != w || ctx == nil {
		return ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.sessionProfile || w.session == nil {
		return ErrInvalid
	}
	if err := w.historyReadyLocked(ctx); err != nil {
		return err
	}
	checkCurrent := func() bool {
		return w.guardRoot(ctx) == nil && w.history.check() == nil &&
			w.history.inflight == "" && w.policyMatches(w.base) && w.historyMatches(w.base)
	}
	if w.guard(ctx) != nil || !checkCurrent() {
		return w.poison(ctx)
	}
	// A visible matching declaration cannot erase a failed return.
	w.attempted = true
	w.at("before-session-closure")
	if w.guard(ctx) != nil || !checkCurrent() || w.session.RecordClosure(ctx, w.base) != nil {
		return w.poison(ctx)
	}
	w.at("after-session-closure")
	if !checkCurrent() {
		return w.poison(ctx)
	}
	d, err := w.session.Observe(ctx, w.base)
	if err != nil || d.Kind() != policyevidence.ClosureMatchesCurrent || !checkCurrent() {
		return w.poison(ctx)
	}
	w.sessionSealed, w.attempted = true, false
	return nil
}
