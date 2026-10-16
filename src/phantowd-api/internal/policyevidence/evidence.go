// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package policyevidence decodes and compares private desired-policy operation
// records in memory. It provides no collector, writer, recovery or admission.
package policyevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

const (
	IntentFormat   = "phantowd-nas-policy-intent"
	ReceiptFormat  = "phantowd-nas-policy-receipt"
	SchemaVersion  = 1
	MaxRecordBytes = 4096
)

var (
	ErrInvalid = errors.New("invalid policy operation evidence")
	ErrPrivate = errors.New("policy operation evidence is internal")
)

type tuple struct {
	InstallationID string `json:"installation_id"`
	OperationID    string `json:"operation_id"`
	BaseRevision   uint64 `json:"base_revision"`
	NextRevision   uint64 `json:"next_revision"`
	BaseSHA256     string `json:"base_sha256"`
	NextSHA256     string `json:"next_sha256"`
}

type record struct {
	Format        string `json:"format"`
	SchemaVersion int    `json:"schema_version"`
	tuple
	Phase string `json:"phase,omitempty"`
}

// Intent and Receipt hold validated private tuples, not provenance or success
// capabilities. Only explicit private codecs serialize them. The zero is invalid.
type Intent struct{ value tuple }
type Receipt struct{ value tuple }

func canonicalHex(value string, length int, nonzero bool) bool {
	if len(value) != length {
		return false
	}
	any := false
	for i := range value {
		c := value[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		any = any || c != '0'
	}
	return !nonzero || any
}

func (t tuple) valid() bool {
	return canonicalHex(t.InstallationID, 32, true) && canonicalHex(t.OperationID, 32, true) &&
		t.BaseRevision > 0 && t.BaseRevision < math.MaxUint64 && t.NextRevision == t.BaseRevision+1 &&
		canonicalHex(t.BaseSHA256, 64, false) && canonicalHex(t.NextSHA256, 64, false)
}

func decode(input io.Reader, receipt bool) (tuple, error) {
	if input == nil {
		return tuple{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(input, MaxRecordBytes+1))
	if err != nil {
		return tuple{}, ErrInvalid
	}
	defer clear(data)
	keys := []string{"format", "schema_version", "installation_id", "operation_id", "base_revision", "next_revision", "base_sha256", "next_sha256"}
	format := IntentFormat
	if receipt {
		keys = append(keys, "phase")
		format = ReceiptFormat
	}
	if _, err := configjson.DecodeEnvelope(data, MaxRecordBytes, 2, keys...); err != nil {
		return tuple{}, ErrInvalid
	}
	var r record
	if json.Unmarshal(data, &r) != nil || r.Format != format || r.SchemaVersion != SchemaVersion || !r.tuple.valid() ||
		(receipt && r.Phase != "local-confirmed") {
		return tuple{}, ErrInvalid
	}
	return r.tuple, nil
}

func DecodeIntent(input io.Reader) (Intent, error) {
	t, err := decode(input, false)
	if err != nil {
		return Intent{}, err
	}
	return Intent{value: t}, nil
}

func DecodeReceipt(input io.Reader) (Receipt, error) {
	t, err := decode(input, true)
	if err != nil {
		return Receipt{}, err
	}
	return Receipt{value: t}, nil
}

// EncodeIntent/EncodeReceipt return private record bytes, not an HTTP document.
// They perform no I/O, generate no identifiers and confirm no transaction.
func EncodeIntent(i Intent) ([]byte, error)   { return encode(i.value, false) }
func EncodeReceipt(r Receipt) ([]byte, error) { return encode(r.value, true) }
func encode(t tuple, receipt bool) ([]byte, error) {
	if !t.valid() {
		return nil, ErrInvalid
	}
	r := record{Format: IntentFormat, SchemaVersion: SchemaVersion, tuple: t}
	if receipt {
		r.Format, r.Phase = ReceiptFormat, "local-confirmed"
	}
	data, err := json.Marshal(r)
	if err != nil || len(data) > MaxRecordBytes {
		return nil, ErrInvalid
	}
	return data, nil
}

// ObservationState describes a trusted caller's complete read of one role.
// Unavailable is deliberately zero. Absence must not represent a failed read.
type ObservationState uint8

const (
	Unavailable ObservationState = iota
	Absent
	Present
)

type Slot struct {
	State ObservationState
	Data  []byte
}

// Evidence is private, caller-owned input, not a filesystem observation token.
// All roles must be known. Do not change the slices concurrently with Match.
// A future retained collector must establish origin/permissions/completeness;
// this pure API cannot prove those assertions or identify rollback/cloned state.
type Evidence struct {
	InstallationID           string
	Intent, Receipt, Current Slot
}

type Kind string

const (
	NoRecordedOperation       Kind = "no-recorded-operation"
	IntentBaseObserved        Kind = "intent-base-observed"
	PublicationUnconfirmed    Kind = "publication-unconfirmed"
	LocalConfirmationObserved Kind = "local-confirmation-observed"
	InconsistentEvidence      Kind = "inconsistent-evidence"
	IncompleteEvidence        Kind = "incomplete-evidence"
)

// Diagnosis exposes only a redacted kind. Every kind grants NO action. Even a
// matching local receipt proves neither past fsync returns nor reply delivery.
type Diagnosis struct{ kind Kind }

func (d Diagnosis) Kind() Kind { return d.kind }

func (s Slot) valid() bool {
	return (s.State == Unavailable || s.State == Absent) && len(s.Data) == 0 || s.State == Present && len(s.Data) > 0
}

func Match(e Evidence) (Diagnosis, error) {
	if !canonicalHex(e.InstallationID, 32, true) || !e.Intent.valid() || !e.Receipt.valid() || !e.Current.valid() {
		return Diagnosis{}, ErrInvalid
	}
	if e.Intent.State == Unavailable || e.Receipt.State == Unavailable || e.Current.State != Present {
		return Diagnosis{kind: IncompleteEvidence}, nil
	}
	var intent Intent
	var receipt Receipt
	var err error
	if e.Intent.State == Present {
		intent, err = DecodeIntent(bytes.NewReader(e.Intent.Data))
		if err != nil {
			return Diagnosis{}, ErrInvalid
		}
	}
	if e.Receipt.State == Present {
		receipt, err = DecodeReceipt(bytes.NewReader(e.Receipt.Data))
		if err != nil {
			return Diagnosis{}, ErrInvalid
		}
	}
	if len(e.Current.Data) > naspolicy.MaxInputBytes {
		return Diagnosis{}, ErrInvalid
	}
	current, err := naspolicy.Decode(bytes.NewReader(e.Current.Data))
	if err != nil {
		return Diagnosis{}, ErrInvalid
	}
	if e.Intent.State == Absent && e.Receipt.State == Absent {
		return Diagnosis{kind: NoRecordedOperation}, nil
	}
	if e.Intent.State == Absent || intent.value.InstallationID != e.InstallationID ||
		(e.Receipt.State == Present && receipt.value != intent.value) {
		return Diagnosis{kind: InconsistentEvidence}, nil
	}
	sum := sha256.Sum256(e.Current.Data)
	digest := hex.EncodeToString(sum[:])
	base := current.Revision == intent.value.BaseRevision && digest == intent.value.BaseSHA256
	next := current.Revision == intent.value.NextRevision && digest == intent.value.NextSHA256
	switch {
	case e.Receipt.State == Present && next:
		return Diagnosis{kind: LocalConfirmationObserved}, nil
	case e.Receipt.State == Absent && base:
		return Diagnosis{kind: IntentBaseObserved}, nil
	case e.Receipt.State == Absent && next:
		return Diagnosis{kind: PublicationUnconfirmed}, nil
	default:
		return Diagnosis{kind: InconsistentEvidence}, nil
	}
}

func (Intent) Format(s fmt.State, _ rune)   { _, _ = io.WriteString(s, "policy-intent{redacted}") }
func (Receipt) Format(s fmt.State, _ rune)  { _, _ = io.WriteString(s, "policy-receipt{redacted}") }
func (Slot) Format(s fmt.State, _ rune)     { _, _ = io.WriteString(s, "policy-evidence-slot{redacted}") }
func (Evidence) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, "policy-evidence{redacted}") }
func (d Diagnosis) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-evidence-diagnosis{"+string(d.kind)+"}")
}
func (Intent) MarshalJSON() ([]byte, error)    { return nil, ErrPrivate }
func (Receipt) MarshalJSON() ([]byte, error)   { return nil, ErrPrivate }
func (Slot) MarshalJSON() ([]byte, error)      { return nil, ErrPrivate }
func (Evidence) MarshalJSON() ([]byte, error)  { return nil, ErrPrivate }
func (Diagnosis) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Intent) UnmarshalJSON([]byte) error     { return ErrPrivate }
func (*Receipt) UnmarshalJSON([]byte) error    { return ErrPrivate }
func (*Slot) UnmarshalJSON([]byte) error       { return ErrPrivate }
func (*Evidence) UnmarshalJSON([]byte) error   { return ErrPrivate }
func (*Diagnosis) UnmarshalJSON([]byte) error  { return ErrPrivate }
