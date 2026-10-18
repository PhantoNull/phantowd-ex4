//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

var sessionFixtureMu sync.Mutex
var retainedSessionFixture *writer

func exerciseHistorySessions(ctx context.Context, initial naspolicy.Config) error {
	sessionFixtureMu.Lock()
	defer sessionFixtureMu.Unlock()
	if retainedSessionFixture != nil {
		return ErrReview
	}
	for _, scenario := range []string{"normal", "missing-restored", "policy-after-error", "cancel-after-closure", "close-open"} {
		if err := exerciseHistorySession(ctx, initial, scenario); err != nil {
			return fmt.Errorf("session fixture %s: %w", scenario, err)
		}
	}
	fmt.Println("PHANTOWD_POLICY_SESSION_WRITER_READY scenarios=5 original_locks=true opening_required=true unified_history=true checkpoint_bound=true closure_serialized=true uncertainty_fenced=true close_does_not_seal=true product=false scope=temporary-qemu-only")
	return ctx.Err()
}

// Independent synthetic-file oracle, not the runtime journal reader or a
// product observer. Exact journal bytes join the original whole-history census.
func sessionWriterSnapshot(w *writer) (map[string][]byte, error) {
	snapshot, err := historyWriterSnapshot(w)
	if err != nil {
		return nil, err
	}
	wire, err := os.ReadFile(filepath.Join(w.path, "policy-session/epoch.json"))
	if err != nil || len(wire) > 12*1024 {
		return nil, ErrReview
	}
	snapshot["session"] = wire
	return snapshot, nil
}

func sessionOpeningUnchanged(before, after []byte, revision uint64) bool {
	var a, b struct {
		Revision uint64 `json:"revision"`
		Opening  string `json:"opening"`
		Closure  string `json:"closure"`
	}
	return json.Unmarshal(before, &a) == nil && json.Unmarshal(after, &b) == nil &&
		a.Revision == 1 && a.Opening != "" && a.Closure == "" &&
		b.Revision == revision && a.Opening == b.Opening &&
		(revision == 1 && b.Closure == "" || revision == 2 && b.Closure != "")
}

// Independent coherent suffix control: ordinary history matching accepts it,
// but the original opening forbids silently rebasing its checkpoint to revision2.
func sessionSuffixRefused(ctx context.Context, w *writer) bool {
	entries, err := w.history.observe()
	if err != nil || len(entries) != 2 {
		return false
	}
	defer func() {
		for _, entry := range entries {
			clear(entry.Operation.Data)
		}
	}()
	for _, entry := range entries {
		b, err := decodeBundle(bytes.NewReader(entry.Operation.Data))
		if err != nil {
			return false
		}
		defer b.clear()
		c, err := naspolicy.Decode(bytes.NewReader(b.base))
		if err != nil {
			return false
		}
		if c.Revision != 2 {
			continue
		}
		suffix := []policyevidence.HistoryOperation{{Base: policyevidence.Slot{State: policyevidence.Present, Data: b.base},
			Intent:  policyevidence.Slot{State: policyevidence.Present, Data: b.intent},
			Receipt: policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}}}
		h, err := policyevidence.MatchHistory(w.installation, suffix[0].Base, policyevidence.Slot{State: policyevidence.Present, Data: w.base}, suffix)
		if err != nil || h.Kind() != policyevidence.LocalConfirmationObserved {
			return false
		}
		d, err := w.session.ObserveHistory(ctx, b.base, w.base, suffix)
		return err == nil && d.Kind() == policyevidence.InconsistentSessionEvidence
	}
	return false
}

// Caller holds the fixture mutex. On uncertain reference closure retain the
// original writer globally; no close retry or unsafe namespace deletion.
func exerciseHistorySession(parent context.Context, initial naspolicy.Config, scenario string) (result error) {
	stage := "construct"
	defer func() {
		if result != nil {
			result = fmt.Errorf("stage=%s: %w", stage, result)
		}
	}()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrReview
	}
	w, err := newDisposableHistorySession(parent, "11111111222233334444555555555555", initial)
	if w != nil {
		defer func() {
			if w.closeFailed || w.close() != nil {
				retainedSessionFixture = w
				result = ErrReview
				return
			}
			if w.discard() != nil {
				retainedSessionFixture = w
				result = ErrReview
				return
			}
			after, e := os.ReadDir("/proc/self/fd")
			if e != nil || len(after) != len(before) {
				result = ErrReview
			}
		}()
	}
	if err != nil {
		return err
	}
	stage = "original-authority"
	if !actualLocksHeld(w) || !rootCensusFor(w.root, true) || rootCensus(w.root) {
		return ErrReview
	}
	copyWriter := *w
	if copyWriter.sealSession(parent) != ErrInvalid {
		return ErrReview
	}
	start, err := sessionWriterSnapshot(w)
	if err != nil {
		return err
	}
	canceled, cancel := context.WithCancel(parent)
	cancel()
	if !errors.Is(w.sealSession(canceled), context.Canceled) || w.review || w.attempted {
		return ErrReview
	}
	after, err := sessionWriterSnapshot(w)
	if err != nil || !equalHistorySnapshot(start, after) {
		return ErrReview
	}
	next, err := draftViewFixture(initial, 2, true)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	epochPath := filepath.Join(w.path, "policy-session/epoch.json")
	stage = scenario
	switch scenario {
	case "close-open":
		if w.close() != nil {
			return ErrReview
		}
		after, err = sessionWriterSnapshot(w)
		if err != nil || !equalHistorySnapshot(start, after) || !sessionOpeningUnchanged(start["session"], after["session"], 1) {
			return ErrReview
		}
		return nil
	case "missing-restored":
		if os.Remove(epochPath) != nil {
			return ErrReview
		}
		if _, e := w.executeFileServicesHistory(ctx, 1, next.FileServices); !errors.Is(e, ErrReview) {
			return ErrReview
		}
		// Test-only restoration does not recover the original writer/journal.
		if os.WriteFile(epochPath, start["session"], 0600) != nil {
			return ErrReview
		}
		after, err = sessionWriterSnapshot(w)
		if err != nil || !equalHistorySnapshot(start, after) {
			return ErrReview
		}
	case "policy-after-error":
		commit := w.policyWrite
		w.policyWrite = func(rev uint64, c naspolicy.Config) error {
			if !actualLocksHeld(w) || commit(rev, c) != nil {
				return ErrReview
			}
			return ErrReview
		}
		if _, e := w.executeFileServicesHistory(ctx, 1, next.FileServices); !errors.Is(e, ErrReview) {
			return ErrReview
		}
		after, err = sessionWriterSnapshot(w)
		if err != nil || !bytes.Equal(start["session"], after["session"]) || bytes.Equal(start["policy"], after["policy"]) || len(w.history.records) != 1 || w.history.inflight == "" {
			return ErrReview
		}
		if !w.sessionHistoryMatches(parent, after["policy"], policyevidence.UnresolvedSessionOperation) {
			return ErrReview
		}
	case "normal", "cancel-after-closure":
		if out, e := w.executeFileServicesHistory(ctx, 1, next.FileServices); e != nil || out.revision != 2 {
			return ErrReview
		}
		next, err = draftViewFixture(next, 3, false)
		if err != nil {
			return err
		}
		if out, e := w.executeISCSIHistory(ctx, 2, next.ISCSI); e != nil || out.revision != 3 {
			return ErrReview
		}
		after, err = sessionWriterSnapshot(w)
		if err != nil || !bytes.Equal(start["session"], after["session"]) || !w.historyMatches(w.base) || len(w.history.records) != 2 {
			return ErrReview
		}
		if !w.sessionHistoryMatches(ctx, w.base, policyevidence.OpenSessionHistoryObserved) || !sessionSuffixRefused(ctx, w) {
			return ErrReview
		}
		if scenario == "cancel-after-closure" {
			w.boundary = func(point string) {
				if point == "after-session-closure" {
					cancel()
				}
			}
		}
		e := w.sealSession(ctx)
		if scenario == "normal" && e != nil || scenario == "cancel-after-closure" && (!errors.Is(e, ErrReview) || !errors.Is(e, context.Canceled)) {
			return ErrReview
		}
		after, err = sessionWriterSnapshot(w)
		if err != nil || !sessionOpeningUnchanged(start["session"], after["session"], 2) || !bytes.Equal(after["policy"], w.base) {
			return ErrReview
		}
		// Matching closure DATA does not override the containing writer's review.
		d, e := w.session.Observe(parent, w.base)
		if e != nil || d.Kind() != policyevidence.ClosureMatchesCurrent {
			return ErrReview
		}
		if !w.sessionHistoryMatches(parent, w.base, policyevidence.ClosureSessionHistoryObserved) {
			return ErrReview
		}
	default:
		return ErrInvalid
	}
	stage = "terminal-no-effect"
	want := ErrReview
	if scenario == "normal" {
		want = ErrAttempted
		if !w.sessionSealed || w.review {
			return ErrReview
		}
	} else if !w.review {
		return ErrReview
	}
	for i := 0; i < 2; i++ {
		if !errors.Is(w.sealSession(parent), want) {
			return ErrReview
		}
		if _, e := w.executeISCSIHistory(parent, next.Revision, next.ISCSI); !errors.Is(e, want) {
			return ErrReview
		}
	}
	last, err := sessionWriterSnapshot(w)
	if err != nil || !equalHistorySnapshot(after, last) || !actualLocksHeld(w) {
		return ErrReview
	}
	if w.close() != nil {
		return ErrReview
	}
	last, err = sessionWriterSnapshot(w)
	if err != nil || !equalHistorySnapshot(after, last) {
		return ErrReview
	}
	return nil
}
