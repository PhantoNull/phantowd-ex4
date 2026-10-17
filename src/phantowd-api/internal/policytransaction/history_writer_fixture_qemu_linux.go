//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func exerciseHistoryWriterQEMU(ctx context.Context, initial naspolicy.Config) error {
	for _, scenario := range []string{"normal", "cancel-after-intent", "cancel-after-policy", "cancel-after-receipt", "policy-after-error", "history-write-open"} {
		if err := exerciseHistoryWriterScenario(ctx, initial, scenario); err != nil {
			return fmt.Errorf("history writer %s: %w", scenario, err)
		}
	}
	fmt.Println("PHANTOWD_POLICY_HISTORY_WRITER_READY operations=2 original_locks=true history_preserved=true uncertainty_fenced=true no_retry=true product=false scope=temporary-qemu-only")
	return ctx.Err()
}

// All paths and state originate in a new disposable writer. This oracle is
// fixture-only, not the runtime reader, recovery or permission to adopt state.
func historyWriterSnapshot(w *writer) (map[string][]byte, error) {
	result := make(map[string][]byte)
	names, err := os.ReadDir(filepath.Join(w.path, "operations"))
	if err != nil || len(names) > policyevidence.MaxHistoryOperations+1 {
		return nil, ErrReview
	}
	for _, entry := range names {
		if !IsHistoryRecordName(entry.Name()) && entry.Name() != journalPending {
			return nil, ErrReview
		}
		data, err := os.ReadFile(filepath.Join(w.path, "operations", entry.Name()))
		if err != nil || len(data) > maxBundleBytes {
			return nil, ErrReview
		}
		result[entry.Name()] = data
	}
	policy, err := os.ReadFile(filepath.Join(w.path, "policy/nas-services.json"))
	if err != nil || len(policy) > naspolicy.MaxInputBytes {
		return nil, ErrReview
	}
	result["policy"] = policy
	return result, nil
}
func equalHistorySnapshot(a, b map[string][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	for name, data := range a {
		if !bytes.Equal(data, b[name]) {
			return false
		}
	}
	return true
}

func exerciseHistoryWriterScenario(parent context.Context, initial naspolicy.Config, scenario string) (result error) {
	const installation = "11111111222233334444555555555555"
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrReview
	}
	w, err := newDisposableHistory(parent, installation, initial)
	if err != nil {
		if w != nil {
			_ = w.close()
		}
		return err
	}
	defer func() {
		if w.close() != nil || w.discard() != nil {
			result = ErrReview
			return
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(after) != len(before) {
			result = ErrReview
		}
	}()
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	next := initial
	fixtureRevision(&next, 2)
	rootFD, journalFD := w.root.Fd(), w.history.dir.Fd()
	if out, err := w.executeHistory(ctx, next); err != nil || out.revision != 2 || !actualLocksHeld(w) {
		return ErrReview
	}
	var firstName string
	var first journalObject
	for firstName, first = range w.history.records {
		break
	}
	if firstName == "" {
		return ErrReview
	}
	firstWire := bytes.Clone(first.wire)
	defer clear(firstWire)
	fixtureRevision(&next, 3)
	if scenario == "normal" {
		var wg sync.WaitGroup
		var outcomes [2]localOutcome
		var failures [2]error
		wg.Add(2)
		for i := range 2 {
			go func(i int) { defer wg.Done(); outcomes[i], failures[i] = w.executeHistory(ctx, next) }(i)
		}
		wg.Wait()
		won, stale := 0, 0
		for i := range failures {
			if failures[i] == nil && outcomes[i].revision == 3 {
				won++
			} else if failures[i] == ErrInvalid && outcomes[i].revision == 0 {
				stale++
			} else {
				return ErrReview
			}
		}
		if won != 1 || stale != 1 || w.review || len(w.history.records) != 2 || !w.historyMatches(w.base) {
			return ErrReview
		}
	} else {
		if scenario == "history-write-open" {
			f, err := os.OpenFile(filepath.Join(w.path, "operations", firstName), os.O_WRONLY, 0)
			if err != nil {
				return ErrReview
			}
			if f.Close() != nil {
				return ErrReview
			}
		} else if scenario == "policy-after-error" {
			actual := w.policyWrite
			w.policyWrite = func(expected uint64, c naspolicy.Config) error {
				if err := actual(expected, c); err != nil {
					return err
				}
				return errors.New("private controlled post-commit failure")
			}
		} else {
			w.boundary = func(stage string) {
				if scenario == "cancel-"+stage {
					cancel(errors.New("private controlled cancellation"))
				}
			}
		}
		out, err := w.executeHistory(ctx, next)
		if out.revision != 0 || !errors.Is(err, ErrReview) || !w.review || !actualLocksHeld(w) {
			return ErrReview
		}
		if scenario != "policy-after-error" && scenario != "history-write-open" && !errors.Is(err, context.Canceled) {
			return ErrReview
		}
		w.boundary = nil
		snapshot, err := historyWriterSnapshot(w)
		if err != nil {
			return err
		}
		// A matching receipt does not override the root Owner's uncertainty.
		if scenario == "cancel-after-receipt" {
			entries, err := w.history.observe()
			if err != nil {
				return ErrReview
			}
			d, err := MatchNamedBundleHistoryObservation(installation,
				policyevidence.Slot{State: policyevidence.Present, Data: w.checkpoint},
				policyevidence.Slot{State: policyevidence.Present, Data: snapshot["policy"]}, entries)
			for _, entry := range entries {
				clear(entry.Operation.Data)
			}
			if err != nil || d.Kind() != policyevidence.LocalConfirmationObserved {
				return ErrReview
			}
		}
		fixtureRevision(&next, 4)
		for range 2 {
			if out, err := w.executeHistory(parent, next); err != ErrReview || out.revision != 0 {
				return ErrReview
			}
			after, err := historyWriterSnapshot(w)
			if err != nil || !equalHistorySnapshot(snapshot, after) {
				return ErrReview
			}
		}
	}
	currentFirst := w.history.records[firstName]
	if currentFirst.file != first.file || currentFirst.stamp != first.stamp || !bytes.Equal(currentFirst.wire, firstWire) || w.root.Fd() != rootFD || w.history.dir.Fd() != journalFD || !actualLocksHeld(w) {
		return ErrReview
	}
	return nil
}
