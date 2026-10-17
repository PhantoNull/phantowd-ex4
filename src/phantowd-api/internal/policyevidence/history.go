// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"fmt"
	"io"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

// Inspection bounds, not a persistent retention policy or permission to delete
// old evidence. A caller must not truncate a history to fit these bounds.
const MaxHistoryOperations = 16
const MaxHistoryInputBytes = 4 << 20

// HistoryOperation is caller-owned private evidence, not a file/transaction
// capability. Base preserves the exact pre-operation policy bytes.
type HistoryOperation struct {
	Base, Intent, Receipt Slot
}

func (HistoryOperation) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*HistoryOperation) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (HistoryOperation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "policy-history-operation{redacted}")
}

// MatchHistory compares a complete caller-supplied history against its trusted
// checkpoint and current policy. No diagnosis authorizes recovery or activation.
// This function cannot establish completeness, provenance or absence of pending
// writes. Inputs must remain unchanged until return.
func MatchHistory(installation string, anchor, current Slot, operations []HistoryOperation) (Diagnosis, error) {
	if len(operations) > MaxHistoryOperations {
		return Diagnosis{}, ErrInvalid
	}
	remaining := MaxHistoryInputBytes
	admit := func(slot Slot, limit int) bool {
		if !slot.valid() || len(slot.Data) > limit || len(slot.Data) > remaining {
			return false
		}
		remaining -= len(slot.Data)
		return true
	}
	if !admit(anchor, naspolicy.MaxInputBytes) || !admit(current, naspolicy.MaxInputBytes) {
		return Diagnosis{}, ErrInvalid
	}
	for _, op := range operations {
		if !admit(op.Base, naspolicy.MaxInputBytes) || !admit(op.Intent, MaxRecordBytes) || !admit(op.Receipt, MaxRecordBytes) {
			return Diagnosis{}, ErrInvalid
		}
	}
	absent := Slot{State: Absent}
	for _, value := range []Slot{anchor, current} {
		if _, err := Match(Evidence{installation, absent, absent, value}); err != nil {
			return Diagnosis{}, ErrInvalid
		}
	}
	type item struct {
		index  int
		intent Intent
	}
	ordered := make([]item, 0, len(operations))
	incomplete := anchor.State != Present || current.State != Present
	inconsistent := false
	for index, op := range operations {
		if !op.Base.valid() || !op.Intent.valid() || !op.Receipt.valid() {
			return Diagnosis{}, ErrInvalid
		}
		if _, err := Match(Evidence{installation, absent, absent, op.Base}); err != nil {
			return Diagnosis{}, ErrInvalid
		}
		var i Intent
		if op.Intent.State == Present {
			var err error
			i, err = DecodeIntent(bytes.NewReader(op.Intent.Data))
			if err != nil {
				return Diagnosis{}, ErrInvalid
			}
		}
		var r Receipt
		if op.Receipt.State == Present {
			var err error
			r, err = DecodeReceipt(bytes.NewReader(op.Receipt.Data))
			if err != nil {
				return Diagnosis{}, ErrInvalid
			}
		}
		if op.Base.State != Present || op.Intent.State != Present || op.Receipt.State == Unavailable {
			incomplete = true
		}
		if op.Intent.State != Present {
			continue
		}
		inconsistent = inconsistent || i.value.InstallationID != installation ||
			(op.Receipt.State == Present && r.value != i.value)
		for _, previous := range ordered {
			if previous.intent.value.OperationID == i.value.OperationID {
				inconsistent = true
			}
		}
		if op.Base.State == Present {
			d, err := Match(Evidence{installation, op.Intent, absent, op.Base})
			if err != nil {
				return Diagnosis{}, ErrInvalid
			}
			inconsistent = inconsistent || d.Kind() != IntentBaseObserved
		}
		ordered = append(ordered, item{index, i})
	}
	if inconsistent {
		return Diagnosis{kind: InconsistentEvidence}, nil
	}
	if incomplete {
		return Diagnosis{kind: IncompleteEvidence}, nil
	}
	if len(ordered) == 0 {
		if !bytes.Equal(anchor.Data, current.Data) {
			return Diagnosis{kind: InconsistentEvidence}, nil
		}
		return Diagnosis{kind: NoRecordedOperation}, nil
	}
	slices.SortFunc(ordered, func(a, b item) int {
		if a.intent.value.BaseRevision < b.intent.value.BaseRevision {
			return -1
		}
		if a.intent.value.BaseRevision > b.intent.value.BaseRevision {
			return 1
		}
		return 0
	})
	if !bytes.Equal(anchor.Data, operations[ordered[0].index].Base.Data) {
		return Diagnosis{kind: InconsistentEvidence}, nil
	}
	for index := 1; index < len(ordered); index++ {
		previous, next := operations[ordered[index-1].index], operations[ordered[index].index]
		d, err := Match(Evidence{installation, previous.Intent, previous.Receipt, next.Base})
		if err != nil || d.Kind() != LocalConfirmationObserved {
			return Diagnosis{kind: InconsistentEvidence}, nil
		}
	}
	last := operations[ordered[len(ordered)-1].index]
	return Match(Evidence{installation, last.Intent, last.Receipt, current})
}
