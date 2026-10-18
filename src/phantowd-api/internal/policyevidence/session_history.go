// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

type SessionKind string

const (
	OpenSessionHistoryObserved    SessionKind = "open-session-history-observed"
	ClosureSessionHistoryObserved SessionKind = "closure-session-history-observed"
	UnresolvedSessionOperation    SessionKind = "unresolved-session-operation"
	IncompleteSessionEvidence     SessionKind = "incomplete-session-evidence"
	InconsistentSessionEvidence   SessionKind = "inconsistent-session-evidence"
)

// Private DATA diagnosis. No kind grants boot, recovery, writes or activation.
type SessionDiagnosis struct{ kind SessionKind }

func (d SessionDiagnosis) Kind() SessionKind { return d.kind }

// MatchSessionHistory joins declarations and complete supplied history against
// the EXACT opening checkpoint, not any later coherent policy. All present data
// is validated before a diagnosis. This cannot establish record/census origin,
// epoch succession, prior successful syscall returns, Close or consumer drain.
// Inputs must remain immutable until return. No input is retained or mutated.
func MatchSessionHistory(installation string, opening, closure, checkpoint, current Slot, operations []HistoryOperation) (SessionDiagnosis, error) {
	if len(operations) > MaxHistoryOperations {
		return SessionDiagnosis{}, ErrInvalid
	}
	remaining := MaxHistoryInputBytes
	admit := func(s Slot, limit int) bool {
		if !s.valid() || len(s.Data) > limit || len(s.Data) > remaining {
			return false
		}
		remaining -= len(s.Data)
		return true
	}
	if !admit(opening, MaxRecordBytes) || !admit(closure, MaxRecordBytes) ||
		!admit(checkpoint, naspolicy.MaxInputBytes) || !admit(current, naspolicy.MaxInputBytes) {
		return SessionDiagnosis{}, ErrInvalid
	}
	for _, op := range operations {
		if !admit(op.Base, naspolicy.MaxInputBytes) || !admit(op.Intent, MaxRecordBytes) || !admit(op.Receipt, MaxRecordBytes) {
			return SessionDiagnosis{}, ErrInvalid
		}
	}
	epoch, epochErr := MatchEpoch(installation, opening, closure, current)
	history, historyErr := MatchHistory(installation, checkpoint, current, operations)
	if epochErr != nil || historyErr != nil {
		return SessionDiagnosis{}, ErrInvalid
	}
	inconsistent := epoch.Kind() == InconsistentEpochEvidence || history.Kind() == InconsistentEvidence
	if opening.State == Present && checkpoint.State == Present {
		o, err := DecodeEpochOpening(bytes.NewReader(opening.Data))
		revision, digest, policyErr := epochPolicy(checkpoint.Data)
		if err != nil || policyErr != nil {
			return SessionDiagnosis{}, ErrInvalid
		}
		inconsistent = inconsistent || o.value.PolicyRevision != revision || o.value.PolicySHA256 != digest
	}
	if inconsistent {
		return SessionDiagnosis{InconsistentSessionEvidence}, nil
	}
	if opening.State != Present || epoch.Kind() == IncompleteEpochEvidence || history.Kind() == IncompleteEvidence {
		return SessionDiagnosis{IncompleteSessionEvidence}, nil
	}
	// A closure declaration with an unresolved tail is NOT a resolved session,
	// even when that declaration independently matches the current policy bytes.
	if history.Kind() == IntentBaseObserved || history.Kind() == PublicationUnconfirmed {
		return SessionDiagnosis{UnresolvedSessionOperation}, nil
	}
	if history.Kind() != NoRecordedOperation && history.Kind() != LocalConfirmationObserved {
		return SessionDiagnosis{}, ErrInvalid
	}
	switch epoch.Kind() {
	case OpenEpochObserved:
		return SessionDiagnosis{OpenSessionHistoryObserved}, nil
	case ClosureMatchesCurrent:
		return SessionDiagnosis{ClosureSessionHistoryObserved}, nil
	default:
		return SessionDiagnosis{}, ErrInvalid
	}
}

func (SessionDiagnosis) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*SessionDiagnosis) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (d SessionDiagnosis) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-session-history{"+string(d.kind)+"}")
}
