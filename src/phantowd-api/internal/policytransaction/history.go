// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyepochjournal"
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
	decoded, err := decodeBundleHistory(anchor, current, operations, names)
	if err != nil {
		return policyevidence.Diagnosis{}, err
	}
	defer decoded.clear()
	d, err := policyevidence.MatchHistory(installation, anchor, current, decoded.entries)
	if err != nil {
		return policyevidence.Diagnosis{}, ErrInvalid
	}
	return d, nil
}

// Read-only DATA bridge for an explicitly selected session/history collector.
// The collector, not this function, must establish complete original-file census
// and locks. No result grants writes, boot, recovery or service authority.
func MatchNamedSessionHistoryObservation(installation string, journal, checkpoint, current policyevidence.Slot, entries []NamedBundleObservation) (policyevidence.SessionDiagnosis, error) {
	if len(entries) > policyevidence.MaxHistoryOperations || len(journal.Data) > policyepochjournal.MaxObservedDocumentBytes {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	names := make([]string, len(entries))
	operations := make([]policyevidence.Slot, len(entries))
	remaining := policyevidence.MaxHistoryInputBytes
	for _, size := range []int{len(journal.Data), len(checkpoint.Data), len(current.Data)} {
		if size > remaining {
			return policyevidence.SessionDiagnosis{}, ErrInvalid
		}
		remaining -= size
	}
	for index, entry := range entries {
		if len(entry.Operation.Data) > remaining {
			return policyevidence.SessionDiagnosis{}, ErrInvalid
		}
		remaining -= len(entry.Operation.Data)
		names[index], operations[index] = entry.Name, entry.Operation
	}
	decoded, err := decodeBundleHistory(checkpoint, current, operations, names)
	if err != nil {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	defer decoded.clear()
	d, err := policyepochjournal.MatchObservedHistory(installation, journal, checkpoint, current, decoded.entries)
	if err != nil {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	return d, nil
}

// Owned decoded data, not another authority or backend. Clear on every exit.
type decodedBundleHistory struct {
	bundles []bundle
	entries []policyevidence.HistoryOperation
}

func (d *decodedBundleHistory) clear() {
	for index := range d.bundles {
		d.bundles[index].clear()
	}
	d.bundles, d.entries = nil, nil
}

func decodeBundleHistory(anchor, current policyevidence.Slot, operations []policyevidence.Slot, names []string) (result decodedBundleHistory, resultErr error) {
	defer func() {
		if resultErr != nil {
			result.clear()
		}
	}()
	if len(operations) > policyevidence.MaxHistoryOperations {
		return result, ErrInvalid
	}
	if names != nil && len(names) != len(operations) {
		return result, ErrInvalid
	}
	for index, name := range names {
		if !IsHistoryRecordName(name) {
			return result, ErrInvalid
		}
		for previous := 0; previous < index; previous++ {
			if names[previous] == name {
				return result, ErrInvalid
			}
		}
	}
	remaining := policyevidence.MaxHistoryInputBytes
	for _, size := range []int{len(anchor.Data), len(current.Data)} {
		if size > remaining {
			return result, ErrInvalid
		}
		remaining -= size
	}
	for _, slot := range operations {
		if !validObservedBundleSlot(slot) || len(slot.Data) > remaining {
			return result, ErrInvalid
		}
		remaining -= len(slot.Data)
	}
	result.bundles = make([]bundle, 0, len(operations))
	result.entries = make([]policyevidence.HistoryOperation, len(operations))
	for index, slot := range operations {
		if slot.State != policyevidence.Present {
			continue
		}
		b, err := decodeBundle(bytes.NewReader(slot.Data))
		if err != nil {
			return result, ErrInvalid
		}
		result.bundles = append(result.bundles, b)
		if names != nil {
			i, err := policyevidence.DecodeIntent(bytes.NewReader(b.intent))
			if err != nil || !IsHistoryRecordName(names[index]) || !i.MatchesOperationID(names[index][:32]) {
				return result, ErrInvalid
			}
		}
		result.entries[index] = policyevidence.HistoryOperation{
			Base:    policyevidence.Slot{State: policyevidence.Present, Data: b.base},
			Intent:  policyevidence.Slot{State: policyevidence.Present, Data: b.intent},
			Receipt: policyevidence.Slot{State: policyevidence.Absent},
		}
		if b.revision == 2 {
			result.entries[index].Receipt = policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}
		}
	}
	return result, nil
}

func validObservedBundleSlot(slot policyevidence.Slot) bool {
	return (slot.State == policyevidence.Present || slot.State == policyevidence.Absent || slot.State == policyevidence.Unavailable) &&
		(slot.State == policyevidence.Present) == (len(slot.Data) > 0) && len(slot.Data) <= MaxObservedBundleBytes
}
