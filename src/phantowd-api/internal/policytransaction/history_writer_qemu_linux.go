//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func (w *writer) historyMatches(current []byte) bool {
	entries, err := w.history.observe()
	defer func() {
		for _, entry := range entries {
			clear(entry.Operation.Data)
		}
	}()
	if err != nil {
		return false
	}
	d, err := MatchNamedBundleHistoryObservation(w.installation,
		policyevidence.Slot{State: policyevidence.Present, Data: w.checkpoint},
		policyevidence.Slot{State: policyevidence.Present, Data: current}, entries)
	want := policyevidence.LocalConfirmationObserved
	if len(entries) == 0 {
		want = policyevidence.NoRecordedOperation
	}
	return err == nil && d.Kind() == want
}

// Private extension over newly created disposable state only. One admitted
// operation may succeed and leave a new epoch ready; any uncertain return fences
// the entire lifetime, never just its ID. No existing-state admission/retry,
// observer-to-writer promotion, service consumer or HTTP route is introduced.
func (w *writer) executeHistory(ctx context.Context, next naspolicy.Config) (localOutcome, error) {
	if w == nil || w.self != w || ctx == nil {
		return localOutcome{}, ErrInvalid
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.executeHistoryLocked(ctx, next)
}

// Caller holds the original writer mutex across candidate construction and all
// journal/policy/receipt effects. Neither views nor whole documents can create
// another authority or bypass this same lifetime's uncertainty fence.
func (w *writer) historyReadyLocked(ctx context.Context) error {
	if w.history == nil {
		return ErrInvalid
	}
	if w.closed || w.closeFailed || w.review || w.attempted {
		return ErrReview
	}
	if w.sessionSealed {
		return ErrAttempted
	}
	return ctx.Err()
}

func (w *writer) executeHistoryLocked(ctx context.Context, next naspolicy.Config) (localOutcome, error) {
	if err := w.historyReadyLocked(ctx); err != nil {
		return localOutcome{}, err
	}
	guard := func() bool { return w.guard(ctx) == nil && w.history.check() == nil }
	if !guard() || !w.historyMatches(w.base) {
		return localOutcome{}, w.poison(ctx)
	}
	previous, raw, err := w.policyRead()
	defer clear(raw)
	if err != nil || !bytes.Equal(raw, w.base) || w.history.inflight != "" {
		return localOutcome{}, w.poison(ctx)
	}
	p, err := policyevidence.Prepare(w.installation, raw, next)
	if err != nil {
		if errors.Is(err, policyevidence.ErrPreparation) {
			return localOutcome{}, policyevidence.ErrPreparation
		}
		return localOutcome{}, ErrInvalid
	}
	candidate, err := p.CandidateBytes()
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	defer clear(candidate)
	owned, err := naspolicy.Decode(bytes.NewReader(candidate))
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	intent, err := intentBundle(w.installation, p)
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	defer intent.clear()
	i, err := p.Intent()
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	name, err := i.OperationRecordName()
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	// Preflight the larger local-confirmed encoding BEFORE any effect. This
	// data declaration is not used as evidence until policy commit/readback.
	confirmed, err := confirmedBundle(intent)
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	defer confirmed.clear()
	wire, err := json.Marshal(confirmed)
	if err != nil {
		return localOutcome{}, ErrInvalid
	}
	defer clear(wire)
	if len(w.history.records) >= policyevidence.MaxHistoryOperations || w.history.bytes+len(wire)+len(w.checkpoint)+len(candidate) > policyevidence.MaxHistoryInputBytes {
		return localOutcome{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return localOutcome{}, err
	}
	if !guard() {
		return localOutcome{}, w.poison(ctx)
	}
	w.attempted = true
	w.at("before-intent")
	if !guard() || w.history.begin(name, intent) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-intent")
	if !guard() {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("before-policy")
	if !guard() || w.policyWrite(previous.Revision, owned) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-policy")
	if !guard() || !w.policyMatches(candidate) {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-readback")
	if !guard() {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("before-receipt")
	if !guard() || !w.policyMatches(candidate) || w.history.confirm(name, confirmed) != nil {
		return localOutcome{}, w.poison(ctx)
	}
	w.at("after-receipt")
	if !guard() || !w.policyMatches(candidate) {
		return localOutcome{}, w.poison(ctx)
	}
	// Joined history includes the exact legacy MatchHistory comparison. Old
	// two-role profiles retain their original comparison and final guard.
	historyMatches := false
	if w.sessionProfile {
		historyMatches = w.sessionHistoryMatches(ctx, candidate, policyevidence.OpenSessionHistoryObserved)
	} else {
		historyMatches = w.historyMatches(candidate)
	}
	if !historyMatches || !guard() {
		return localOutcome{}, w.poison(ctx)
	}
	clear(w.base)
	w.base = bytes.Clone(candidate)
	w.attempted, w.confirmed = false, true
	return localOutcome{revision: owned.Revision}, nil
}
