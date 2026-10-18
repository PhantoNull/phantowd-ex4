// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func sessionHistoryPair(t testing.TB, checkpoint, current []byte) (Slot, Slot) {
	t.Helper()
	o, err := DeclareEpochOpening(installation, operation, math.MaxUint64, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	opening, _ := EncodeEpochOpening(o)
	c, err := DeclareEpochClosure(opening, current)
	if err != nil {
		t.Fatal(err)
	}
	closure, _ := EncodeEpochClosure(c)
	return Slot{Present, opening}, Slot{Present, closure}
}

func TestSessionHistoryJoinsExactOpeningAndCompleteChain(t *testing.T) {
	for _, name := range []string{"open", "closed", "empty-open", "empty-closed", "unconfirmed", "unconfirmed-closed", "intent-base", "missing-opening", "missing-checkpoint", "missing-current", "missing-operation", "unknown-closure", "foreign", "orphan-closure", "gap", "duplicate", "changed-current", "changed-opening", "later-checkpoint", "old-opening-base"} {
		t.Run(name, func(t *testing.T) {
			anchor, current, ops := historyChain(t, 2, 0)
			o, c := sessionHistoryPair(t, anchor.Data, current.Data)
			id := installation
			want := ClosureSessionHistoryObserved
			switch name {
			case "open":
				c, want = Slot{State: Absent}, OpenSessionHistoryObserved
			case "empty-open", "empty-closed":
				current, ops = anchor, nil
				o, c = sessionHistoryPair(t, anchor.Data, current.Data)
				if name == "empty-open" {
					c, want = Slot{State: Absent}, OpenSessionHistoryObserved
				}
			case "unconfirmed", "unconfirmed-closed", "intent-base":
				ops[1].Receipt = Slot{State: Absent}
				want = UnresolvedSessionOperation
				if name != "unconfirmed-closed" {
					c = Slot{State: Absent}
				}
				if name == "intent-base" {
					current = ops[1].Base
				}
			case "missing-opening":
				o, c, want = Slot{State: Absent}, Slot{State: Absent}, IncompleteSessionEvidence
			case "missing-checkpoint":
				anchor, want = Slot{State: Absent}, IncompleteSessionEvidence
			case "missing-current":
				current, want = Slot{}, IncompleteSessionEvidence
			case "missing-operation":
				ops[0], want = HistoryOperation{}, IncompleteSessionEvidence
			case "unknown-closure":
				c, want = Slot{}, IncompleteSessionEvidence
			case "foreign":
				id, want = strings.Repeat("a", 32), InconsistentSessionEvidence
			case "orphan-closure":
				o, want = Slot{State: Absent}, InconsistentSessionEvidence
			case "gap":
				ops, want = ops[1:], InconsistentSessionEvidence
			case "duplicate":
				ops[1], want = ops[0], InconsistentSessionEvidence
			case "changed-current":
				current.Data, want = append(bytes.Clone(current.Data), '\n'), InconsistentSessionEvidence
			case "changed-opening":
				o.Data, want = append(bytes.Clone(o.Data), '\n'), InconsistentSessionEvidence
			case "later-checkpoint":
				anchor, ops, want = ops[1].Base, ops[1:], InconsistentSessionEvidence
				// Both earlier independent comparisons accept these inputs.
				if e, err := MatchEpoch(id, o, c, current); err != nil || e.Kind() != ClosureMatchesCurrent {
					t.Fatal("invalid independent epoch control")
				}
				if h, err := MatchHistory(id, anchor, current, ops); err != nil || h.Kind() != LocalConfirmationObserved {
					t.Fatal("invalid independent suffix-history control")
				}
			case "old-opening-base":
				o, c = sessionHistoryPair(t, policy(t, 6), current.Data)
				want = InconsistentSessionEvidence
			}
			d, err := MatchSessionHistory(id, o, c, anchor, current, ops)
			if err != nil || d.Kind() != want {
				t.Fatalf("unexpected redacted diagnosis: %v %v want=%s", d, err, want)
			}
			if _, err := json.Marshal(d); !errors.Is(err, ErrPrivate) || strings.Contains(fmt.Sprintf("%+v %#v", d, d), installation) {
				t.Fatal("session diagnosis disclosed private data")
			}
		})
	}
}

func TestSessionHistoryValidatesPresentDataBeforeDiagnosis(t *testing.T) {
	for _, field := range []string{"opening", "closure", "anchor", "current", "base", "intent", "receipt"} {
		for _, missing := range []bool{false, true} {
			anchor, current, ops := historyChain(t, 2, 0)
			o, c := sessionHistoryPair(t, anchor.Data, current.Data)
			if missing {
				o, anchor = Slot{}, Slot{}
			}
			bad := Slot{Present, []byte(`{"malformed":true}`)}
			switch field {
			case "opening":
				o = bad
			case "closure":
				c = bad
			case "anchor":
				anchor = bad
			case "current":
				current = bad
			case "base":
				ops[1].Base = bad
			case "intent":
				ops[1].Intent = bad
			case "receipt":
				ops[1].Receipt = bad
			}
			if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != ErrInvalid || d != (SessionDiagnosis{}) {
				t.Fatal("malformed present data returned a partial diagnosis", field, missing)
			}
		}
	}
	anchor, current, ops := historyChain(t, 2, 0)
	o, c := sessionHistoryPair(t, policy(t, 6), current.Data)
	ops[0] = HistoryOperation{}
	if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != nil || d.Kind() != InconsistentSessionEvidence {
		t.Fatal("known opening/checkpoint mismatch hidden by missing operation")
	}
}

func TestSessionHistoryBoundsAndConcurrentImmutableInputs(t *testing.T) {
	anchor, current, ops := historyChain(t, MaxHistoryOperations, 0)
	o, c := sessionHistoryPair(t, anchor.Data, current.Data)
	before, _ := json.Marshal([][]byte{o.Data, c.Data, anchor.Data, current.Data, ops[0].Base.Data})
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Go(func() {
			d, err := MatchSessionHistory(installation, o, c, anchor, current, ops)
			if err != nil || d.Kind() != ClosureSessionHistoryObserved {
				t.Error("concurrent complete maximum-count history refused")
			}
		})
	}
	wg.Wait()
	after, _ := json.Marshal([][]byte{o.Data, c.Data, anchor.Data, current.Data, ops[0].Base.Data})
	if !bytes.Equal(before, after) {
		t.Fatal("caller data mutated")
	}
	ops = append(ops, ops[0])
	if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != ErrInvalid || d != (SessionDiagnosis{}) {
		t.Fatal("count limit bypass")
	}
	anchor, current, ops = historyChain(t, 7, 512<<10)
	o, c = sessionHistoryPair(t, anchor.Data, current.Data)
	if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != ErrInvalid || d != (SessionDiagnosis{}) {
		t.Fatal("aggregate limit bypass")
	}
	anchor, current, ops = historyChain(t, 2, 0)
	o, _ = sessionHistoryPair(t, anchor.Data, current.Data)
	o.Data = append(o.Data, bytes.Repeat([]byte{' '}, MaxRecordBytes-len(o.Data))...)
	closure, err := DeclareEpochClosure(o.Data, current.Data)
	if err != nil {
		t.Fatal(err)
	}
	c.Data, _ = EncodeEpochClosure(closure)
	c.State = Present
	c.Data = append(c.Data, bytes.Repeat([]byte{' '}, MaxRecordBytes-len(c.Data))...)
	if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != nil || d.Kind() != ClosureSessionHistoryObserved {
		t.Fatal("inclusive record bounds refused")
	}
	o.Data = append(o.Data, ' ')
	if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != ErrInvalid || d != (SessionDiagnosis{}) {
		t.Fatal("record bound bypass")
	}
	var empty SessionDiagnosis
	if !errors.Is(json.Unmarshal([]byte(`{}`), &empty), ErrPrivate) {
		t.Fatal("generic session JSON accepted")
	}
}

func FuzzSessionHistoryDoesNotReturnPartialInvalidDiagnosis(f *testing.F) {
	anchor, current, ops := historyChain(f, 2, 0)
	o, c := sessionHistoryPair(f, anchor.Data, current.Data)
	f.Add(o.Data)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, opening []byte) {
		if len(opening) > MaxRecordBytes+1 {
			t.Skip()
		}
		d, err := MatchSessionHistory(installation, Slot{Present, opening}, c, anchor, current, ops)
		if err != nil && d != (SessionDiagnosis{}) {
			t.Fatal("invalid input exposed partial diagnosis")
		}
		if err == nil && d.Kind() != ClosureSessionHistoryObserved && d.Kind() != InconsistentSessionEvidence {
			t.Fatal("unexpected fuzz diagnosis")
		}
	})
}

func TestSessionHistoryInclusiveAggregateLimit(t *testing.T) {
	anchor, current, ops := historyChain(t, 6, 500<<10)
	o, c := sessionHistoryPair(t, anchor.Data, current.Data)
	total := len(o.Data) + len(c.Data) + len(anchor.Data) + len(current.Data)
	for _, op := range ops {
		total += len(op.Base.Data) + len(op.Intent.Data) + len(op.Receipt.Data)
	}
	remaining := MaxHistoryInputBytes - total
	if remaining < 0 || len(current.Data)+remaining > naspolicy.MaxInputBytes {
		t.Fatal("invalid bounded fixture construction")
	}
	current.Data = append(bytes.Clone(current.Data), bytes.Repeat([]byte{' '}, remaining)...)
	i, err := DecodeIntent(bytes.NewReader(ops[len(ops)-1].Intent.Data))
	if err != nil {
		t.Fatal(err)
	}
	i.value.NextSHA256 = digest(current.Data)
	ops[len(ops)-1].Intent.Data, _ = EncodeIntent(i)
	ops[len(ops)-1].Receipt.Data, _ = EncodeReceipt(Receipt{value: i.value})
	o, c = sessionHistoryPair(t, anchor.Data, current.Data)
	total = len(o.Data) + len(c.Data) + len(anchor.Data) + len(current.Data)
	for _, op := range ops {
		total += len(op.Base.Data) + len(op.Intent.Data) + len(op.Receipt.Data)
	}
	if total != MaxHistoryInputBytes {
		t.Fatal("fixture not exactly inclusive aggregate limit")
	}
	if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != nil || d.Kind() != ClosureSessionHistoryObserved {
		t.Fatal("inclusive combined aggregate refused", d, err)
	}
	current.Data = append(current.Data, ' ')
	if d, err := MatchSessionHistory(installation, o, c, anchor, current, ops); err != ErrInvalid || d != (SessionDiagnosis{}) {
		t.Fatal("one-byte aggregate overflow accepted")
	}
}

// Native cost diagnostic for identical immutable DATA, not ARM time, retained
// file I/O, peak RSS or product throughput. Both branches include all checks.
func BenchmarkSessionHistoryJoinedVersusRedundant(b *testing.B) {
	anchor, current, ops := historyChain(b, 2, 0)
	o, c := sessionHistoryPair(b, anchor.Data, current.Data)
	for _, redundant := range []bool{true, false} {
		name := "joined-only"
		if redundant {
			name = "redundant-independent-and-joined"
		}
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if redundant {
					e, err := MatchEpoch(installation, o, c, current)
					if err != nil || e.Kind() != ClosureMatchesCurrent {
						b.Fatal("epoch control")
					}
					h, err := MatchHistory(installation, anchor, current, ops)
					if err != nil || h.Kind() != LocalConfirmationObserved {
						b.Fatal("history control")
					}
				}
				d, err := MatchSessionHistory(installation, o, c, anchor, current, ops)
				if err != nil || d.Kind() != ClosureSessionHistoryObserved {
					b.Fatal("joined control")
				}
			}
		})
	}
}
