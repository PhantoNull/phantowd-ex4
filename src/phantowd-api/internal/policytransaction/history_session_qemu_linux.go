//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// The caller holds the original writer mutex and all role locks. History data
// comes from the retained file census, current from its exact readback. Journal
// comparison borrows DATA only, not paths/ownership or per-operation backends.
func (w *writer) sessionHistoryMatches(ctx context.Context, current []byte, want policyevidence.SessionKind) bool {
	entries, err := w.history.observe()
	if err != nil {
		return false
	}
	defer func() {
		for _, entry := range entries {
			clear(entry.Operation.Data)
		}
	}()
	names := make([]string, len(entries))
	operations := make([]policyevidence.Slot, len(entries))
	for index, entry := range entries {
		names[index], operations[index] = entry.Name, entry.Operation
	}
	checkpoint := policyevidence.Slot{State: policyevidence.Present, Data: w.checkpoint}
	observed := policyevidence.Slot{State: policyevidence.Present, Data: current}
	decoded, err := decodeBundleHistory(checkpoint, observed, operations, names)
	if err != nil {
		return false
	}
	defer decoded.clear()
	d, err := w.session.ObserveHistory(ctx, w.checkpoint, current, decoded.entries)
	return err == nil && d.Kind() == want
}

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
	checkCurrent := func(want policyevidence.SessionKind) bool {
		return w.guardRoot(ctx) == nil && w.history.check() == nil &&
			w.history.inflight == "" && w.policyMatches(w.base) && w.sessionHistoryMatches(ctx, w.base, want)
	}
	// The joined comparison invokes the SAME strict epoch/history matchers.
	// Do not decode both complete histories again at the same boundary.
	if !checkCurrent(policyevidence.OpenSessionHistoryObserved) {
		return w.poison(ctx)
	}
	// A visible matching declaration cannot erase a failed return.
	w.attempted = true
	w.at("before-session-closure")
	if !checkCurrent(policyevidence.OpenSessionHistoryObserved) || w.session.RecordClosure(ctx, w.base) != nil {
		return w.poison(ctx)
	}
	w.at("after-session-closure")
	if !checkCurrent(policyevidence.ClosureSessionHistoryObserved) ||
		w.guardRoot(ctx) != nil || w.history.check() != nil || !w.policyMatches(w.base) || ctx.Err() != nil {
		return w.poison(ctx)
	}
	w.sessionSealed, w.attempted = true, false
	return nil
}
