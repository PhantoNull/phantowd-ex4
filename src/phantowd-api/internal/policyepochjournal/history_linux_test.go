//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyepochjournal

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func TestJournalHistoryObservationRechecksOriginalAndDoesNotWrite(t *testing.T) {
	j, _, root := journalFixture(t)
	ctx := context.Background()
	base, next := policyAt(t, 1), policyAt(t, 2)
	if d, err := j.ObserveHistory(ctx, base, base, nil); err != ErrConflict || d.Kind() != "" {
		t.Fatal("empty role manufactured session history")
	}
	if err := j.RecordOpening(ctx, base); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "policy-session/epoch.json")
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		checkpoint, current []byte
		want                policyevidence.SessionKind
	}{{base, base, policyevidence.OpenSessionHistoryObserved},
		{next, next, policyevidence.InconsistentSessionEvidence},
		{base, next, policyevidence.InconsistentSessionEvidence}} {
		d, err := j.ObserveHistory(ctx, tc.checkpoint, tc.current, nil)
		if err != nil || d.Kind() != tc.want {
			t.Fatal("journal history comparison", d, err)
		}
	}
	if _, err := j.ObserveHistory(ctx, base, base, []policyevidence.HistoryOperation{{Intent: policyevidence.Slot{State: policyevidence.Present, Data: []byte(`{}`)}}}); err != ErrInvalid {
		t.Fatal("malformed supplied operation admitted")
	}
	copyJournal := *j
	if _, err := copyJournal.ObserveHistory(ctx, base, base, nil); err != ErrInvalid {
		t.Fatal("copied observer admitted")
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := j.ObserveHistory(canceled, base, base, nil); err != context.Canceled {
		t.Fatal("pre-cancel observation admitted")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || j.state.review {
		t.Fatal("data-only refusal mutated/poisoned journal")
	}
	if err := j.RecordClosure(ctx, base); err != nil {
		t.Fatal(err)
	}
	if d, err := j.ObserveHistory(ctx, base, base, nil); err != nil || d.Kind() != policyevidence.ClosureSessionHistoryObserved {
		t.Fatal("closed empty history refused")
	}
	closed, err := os.ReadFile(path)
	if err != nil || os.Remove(path) != nil {
		t.Fatal("synthetic missing-source setup")
	}
	if d, err := j.ObserveHistory(ctx, base, base, nil); !errors.Is(err, ErrReview) || d.Kind() != "" {
		t.Fatal("missing original source admitted")
	}
	if os.WriteFile(path, closed, 0600) != nil {
		t.Fatal("synthetic restore")
	}
	if d, err := j.ObserveHistory(ctx, base, base, nil); !errors.Is(err, ErrReview) || d.Kind() != "" {
		t.Fatal("restoration revived reviewed observation")
	}
	after, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(closed, after) {
		t.Fatal("review observation changed restored evidence")
	}
}
