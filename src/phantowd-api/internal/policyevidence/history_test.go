// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func historyOperation(t testing.TB, base uint64, confirmed bool) HistoryOperation {
	t.Helper()
	before, after := policy(t, base), policy(t, base+1)
	i := Intent{tuple{installation, fmt.Sprintf("%032x", base), base, base + 1, digest(before), digest(after)}}
	intent, err := EncodeIntent(i)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Slot{State: Absent}
	if confirmed {
		wire, err := EncodeReceipt(Receipt{value: i.value})
		if err != nil {
			t.Fatal(err)
		}
		receipt = Slot{State: Present, Data: wire}
	}
	return HistoryOperation{Base: Slot{State: Present, Data: before}, Intent: Slot{State: Present, Data: intent}, Receipt: receipt}
}

func TestHistoryMatchesConfirmedChainIndependentOfEnumeration(t *testing.T) {
	anchor, current := policy(t, 7), policy(t, 9)
	operations := []HistoryOperation{historyOperation(t, 8, true), historyOperation(t, 7, true)}
	before := bytes.Clone(operations[0].Base.Data)
	d, err := MatchHistory(installation, Slot{Present, anchor}, Slot{Present, current}, operations)
	if err != nil || d.Kind() != LocalConfirmationObserved {
		t.Fatal("coherent multi-operation history refused", d, err)
	}
	if !bytes.Equal(before, operations[0].Base.Data) {
		t.Fatal("caller-owned history changed")
	}
}

func TestHistoryRefusesOperationIDReuseAcrossDifferentRevisions(t *testing.T) {
	first, second := historyOperation(t, 7, true), historyOperation(t, 8, true)
	i, err := DecodeIntent(bytes.NewReader(second.Intent.Data))
	if err != nil {
		t.Fatal(err)
	}
	i.value.OperationID = fmt.Sprintf("%032x", uint64(7))
	second.Intent.Data, _ = EncodeIntent(i)
	second.Receipt.Data, _ = EncodeReceipt(Receipt{value: i.value})
	d, err := MatchHistory(installation, Slot{Present, policy(t, 7)}, Slot{Present, policy(t, 9)}, []HistoryOperation{first, second})
	if err != nil || d.Kind() != InconsistentEvidence {
		t.Fatal("reused operation identity was accepted", d, err)
	}
}

func TestHistoryValidatesAllPresentEvidenceBeforeDiagnosing(t *testing.T) {
	for _, reversed := range []bool{false, true} {
		missing := historyOperation(t, 7, true)
		missing.Base = Slot{}
		malformed := historyOperation(t, 8, true)
		malformed.Intent.Data = []byte(`{"private":"not an intent"}`)
		operations := []HistoryOperation{missing, malformed}
		if reversed {
			operations[0], operations[1] = operations[1], operations[0]
		}
		d, err := MatchHistory(installation, Slot{Present, policy(t, 7)}, Slot{Present, policy(t, 9)}, operations)
		if !errors.Is(err, ErrInvalid) || d != (Diagnosis{}) {
			t.Fatal("incomplete evidence hid malformed present record", d, err)
		}
	}
}

func historyChain(t testing.TB, count, padding int) (Slot, Slot, []HistoryOperation) {
	t.Helper()
	policies := make([][]byte, count+1)
	for index := range policies {
		policies[index] = append(policy(t, uint64(7+index)), []byte(strings.Repeat(" ", padding))...)
	}
	operations := make([]HistoryOperation, count)
	for index := range operations {
		base := uint64(7 + index)
		i := Intent{tuple{installation, fmt.Sprintf("%032x", base), base, base + 1, digest(policies[index]), digest(policies[index+1])}}
		intent, _ := EncodeIntent(i)
		receipt, _ := EncodeReceipt(Receipt{value: i.value})
		operations[index] = HistoryOperation{Slot{Present, policies[index]}, Slot{Present, intent}, Slot{Present, receipt}}
	}
	return Slot{Present, policies[0]}, Slot{Present, policies[count]}, operations
}

func TestHistoryBoundsCountAndAggregateBeforeMatching(t *testing.T) {
	for _, tc := range []struct {
		name           string
		count, padding int
	}{
		{"count", 17, 0}, {"aggregate", 7, 512 << 10},
	} {
		t.Run(tc.name, func(t *testing.T) {
			anchor, current, operations := historyChain(t, tc.count, tc.padding)
			d, err := MatchHistory(installation, anchor, current, operations)
			if !errors.Is(err, ErrInvalid) || d != (Diagnosis{}) {
				t.Fatal("over-budget history accepted", d, err)
			}
		})
	}
}

func TestHistoryOperationIsPrivateEvenWhenEmpty(t *testing.T) {
	for _, op := range []HistoryOperation{{}, historyOperation(t, 7, true)} {
		if data, err := json.Marshal(op); !errors.Is(err, ErrPrivate) || len(data) != 0 {
			t.Fatal("history operation serialized", err)
		}
		if strings.Contains(fmt.Sprintf("%+v %#v", op, op), installation) {
			t.Fatal("history formatting exposed installation")
		}
	}
	var op HistoryOperation
	if !errors.Is(json.Unmarshal([]byte(`{}`), &op), ErrPrivate) {
		t.Fatal("generic JSON accepted an empty history operation")
	}
}

func TestHistoryDiagnosesGapsForksAndUncertainTailWithoutRecovery(t *testing.T) {
	for _, name := range []string{"confirmed", "gap", "fork", "duplicate", "missing-first", "changed-anchor", "changed-current", "unconfirmed-tail", "base-tail", "unconfirmed-interior", "missing-current", "missing-anchor", "missing-base", "missing-intent", "unknown-receipt", "foreign", "receipt-mismatch", "empty", "empty-changed"} {
		t.Run(name, func(t *testing.T) {
			anchor, current, ops := historyChain(t, 2, 0)
			want := InconsistentEvidence
			switch name {
			case "confirmed":
				want = LocalConfirmationObserved
			case "gap":
				ops[1] = historyOperation(t, 9, true)
				current.Data = policy(t, 10)
			case "fork":
				ops[1] = historyOperation(t, 7, true)
				i, _ := DecodeIntent(bytes.NewReader(ops[1].Intent.Data))
				i.value.OperationID = strings.Repeat("a", 32)
				ops[1].Intent.Data, _ = EncodeIntent(i)
				ops[1].Receipt.Data, _ = EncodeReceipt(Receipt{value: i.value})
			case "duplicate":
				ops[1] = ops[0]
			case "missing-first":
				ops = ops[1:]
			case "changed-anchor":
				anchor.Data = append(bytes.Clone(anchor.Data), ' ')
			case "changed-current":
				current.Data = append(bytes.Clone(current.Data), ' ')
			case "unconfirmed-tail", "base-tail":
				ops[1].Receipt = Slot{State: Absent}
				want = PublicationUnconfirmed
				if name == "base-tail" {
					current = ops[1].Base
					want = IntentBaseObserved
				}
			case "unconfirmed-interior":
				ops[0].Receipt = Slot{State: Absent}
			case "missing-current":
				current = Slot{}
				want = IncompleteEvidence
			case "missing-anchor":
				anchor = Slot{State: Absent}
				want = IncompleteEvidence
			case "missing-base":
				ops[0].Base = Slot{}
				want = IncompleteEvidence
			case "missing-intent":
				ops[0].Intent = Slot{State: Absent}
				want = IncompleteEvidence
			case "unknown-receipt":
				ops[0].Receipt = Slot{}
				want = IncompleteEvidence
			case "foreign":
				i, _ := DecodeIntent(bytes.NewReader(ops[0].Intent.Data))
				i.value.InstallationID = strings.Repeat("a", 32)
				ops[0].Intent.Data, _ = EncodeIntent(i)
				ops[0].Receipt.Data, _ = EncodeReceipt(Receipt{value: i.value})
			case "receipt-mismatch":
				ops[0].Receipt = ops[1].Receipt
			case "empty", "empty-changed":
				ops = nil
				if name == "empty" {
					current = anchor
					want = NoRecordedOperation
				}
			}
			for range 2 {
				d, err := MatchHistory(installation, anchor, current, ops)
				if err != nil || d.Kind() != want {
					t.Fatal("history diagnosis", d, err, want)
				}
				if len(ops) == 2 {
					ops[0], ops[1] = ops[1], ops[0]
				}
			}
		})
	}
}

func historyBytes(anchor, current Slot, ops []HistoryOperation) int {
	size := len(anchor.Data) + len(current.Data)
	for _, op := range ops {
		size += len(op.Base.Data) + len(op.Intent.Data) + len(op.Receipt.Data)
	}
	return size
}

func TestHistoryInclusiveInspectionLimits(t *testing.T) {
	anchor, current, ops := historyChain(t, MaxHistoryOperations, 0)
	if d, err := MatchHistory(installation, anchor, current, ops); err != nil || d.Kind() != LocalConfirmationObserved {
		t.Fatal("inclusive count refused", d, err)
	}
	anchor, current, ops = historyChain(t, 7, 0)
	padding := (MaxHistoryInputBytes - historyBytes(anchor, current, ops)) / 9
	anchor, current, ops = historyChain(t, 7, padding)
	current.Data = append(bytes.Clone(current.Data), bytes.Repeat([]byte{' '}, MaxHistoryInputBytes-historyBytes(anchor, current, ops))...)
	last := &ops[len(ops)-1]
	bindTail := func() {
		i, _ := DecodeIntent(bytes.NewReader(last.Intent.Data))
		i.value.NextSHA256 = digest(current.Data)
		last.Intent.Data, _ = EncodeIntent(i)
		last.Receipt.Data, _ = EncodeReceipt(Receipt{value: i.value})
	}
	bindTail()
	if historyBytes(anchor, current, ops) != MaxHistoryInputBytes {
		t.Fatal("test did not reach exact aggregate bound")
	}
	if d, err := MatchHistory(installation, anchor, current, ops); err != nil || d.Kind() != LocalConfirmationObserved {
		t.Fatal("inclusive byte bound refused", d, err)
	}
	current.Data = append(current.Data, ' ')
	bindTail()
	if d, err := MatchHistory(installation, anchor, current, ops); !errors.Is(err, ErrInvalid) || d != (Diagnosis{}) {
		t.Fatal("one byte beyond aggregate accepted", d, err)
	}
}

func TestHistoryExactByteMutationCannotRetainConfirmation(t *testing.T) {
	for index := range 64 {
		anchor, current, ops := historyChain(t, 2, 0)
		ops[1].Base.Data = bytes.Clone(ops[1].Base.Data)
		at := (index * 31) % len(ops[1].Base.Data)
		ops[1].Base.Data[at] ^= 1
		d, err := MatchHistory(installation, anchor, current, ops)
		if err != nil {
			if !errors.Is(err, ErrInvalid) || d != (Diagnosis{}) {
				t.Fatal("mutation gave partial diagnosis", d, err)
			}
		} else if d.Kind() != InconsistentEvidence {
			t.Fatal("altered exact base kept confirmation", d)
		}
	}
}
