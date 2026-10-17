// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// MatchBundleHistoryObservation applies the anchored history comparison to the
// existing experimental per-operation codec. It does not adopt those bytes as
// a product format or establish complete enumeration, provenance, durable
// confirmation, absence of pending files or authority to write/recover/start.
// Bounds never authorize dropping older entries or changing the checkpoint.
func MatchBundleHistoryObservation(installation string, anchor, current policyevidence.Slot, operations []policyevidence.Slot) (policyevidence.Diagnosis, error) {
	return matchBundleHistoryObservation(installation, anchor, current, operations, nil)
}

// NamedBundleObservation is private caller-owned naming/content evidence. Names
// are experimental basenames, not paths, provenance or publication authority.
type NamedBundleObservation struct {
	Name      string
	Operation policyevidence.Slot
}

func (NamedBundleObservation) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*NamedBundleObservation) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (NamedBundleObservation) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, "named-policy-bundle{private}")
}

// IsHistoryRecordName checks the fixed experimental nonzero128-bit lowercase
// operation-ID basename. It performs no content check or filesystem operation.
func IsHistoryRecordName(name string) bool {
	if len(name) != 37 || name[32:] != ".json" {
		return false
	}
	nonzero := false
	for _, ch := range []byte(name[:32]) {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
		nonzero = nonzero || ch != '0'
	}
	return nonzero
}

func MatchNamedBundleHistoryObservation(installation string, anchor, current policyevidence.Slot, entries []NamedBundleObservation) (policyevidence.Diagnosis, error) {
	if len(entries) > policyevidence.MaxHistoryOperations {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	names := make([]string, len(entries))
	operations := make([]policyevidence.Slot, len(entries))
	for index, entry := range entries {
		if !IsHistoryRecordName(entry.Name) {
			return policyevidence.Diagnosis{}, ErrInvalid
		}
		for previous := 0; previous < index; previous++ {
			if names[previous] == entry.Name {
				return policyevidence.Diagnosis{}, ErrInvalid
			}
		}
		names[index], operations[index] = entry.Name, entry.Operation
	}
	return matchBundleHistoryObservation(installation, anchor, current, operations, names)
}

func matchBundleHistoryObservation(installation string, anchor, current policyevidence.Slot, operations []policyevidence.Slot, names []string) (policyevidence.Diagnosis, error) {
	if len(operations) > policyevidence.MaxHistoryOperations {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	remaining := policyevidence.MaxHistoryInputBytes
	for _, size := range []int{len(anchor.Data), len(current.Data)} {
		if size > remaining {
			return policyevidence.Diagnosis{}, ErrInvalid
		}
		remaining -= size
	}
	for _, slot := range operations {
		if !validObservedBundleSlot(slot) || len(slot.Data) > remaining {
			return policyevidence.Diagnosis{}, ErrInvalid
		}
		remaining -= len(slot.Data)
	}
	owned := make([]bundle, 0, len(operations))
	defer func() {
		for index := range owned {
			owned[index].clear()
		}
	}()
	entries := make([]policyevidence.HistoryOperation, len(operations))
	for index, slot := range operations {
		if slot.State != policyevidence.Present {
			continue
		}
		b, err := decodeBundle(bytes.NewReader(slot.Data))
		if err != nil {
			return policyevidence.Diagnosis{}, ErrInvalid
		}
		owned = append(owned, b)
		if names != nil {
			i, err := policyevidence.DecodeIntent(bytes.NewReader(b.intent))
			if err != nil || !i.MatchesOperationID(names[index][:32]) {
				return policyevidence.Diagnosis{}, ErrInvalid
			}
		}
		entries[index] = policyevidence.HistoryOperation{
			Base:    policyevidence.Slot{State: policyevidence.Present, Data: b.base},
			Intent:  policyevidence.Slot{State: policyevidence.Present, Data: b.intent},
			Receipt: policyevidence.Slot{State: policyevidence.Absent},
		}
		if b.revision == 2 {
			entries[index].Receipt = policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}
		}
	}
	d, err := policyevidence.MatchHistory(installation, anchor, current, entries)
	if err != nil {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	return d, nil
}

func validObservedBundleSlot(slot policyevidence.Slot) bool {
	return (slot.State == policyevidence.Present || slot.State == policyevidence.Absent || slot.State == policyevidence.Unavailable) &&
		(slot.State == policyevidence.Present) == (len(slot.Data) > 0) && len(slot.Data) <= MaxObservedBundleBytes
}
