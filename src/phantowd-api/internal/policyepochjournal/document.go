// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package policyepochjournal records experimental policy-session declarations.
// It grants no boot, recovery, consumer, persistence-medium or service authority.
package policyepochjournal

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

const maxDocumentBytes = 12 << 10

// Fixed read-only observation bound, not a product on-disk compatibility pledge.
const MaxObservedDocumentBytes = maxDocumentBytes
const documentFormat = "phantowd-policy-session-journal-experimental"

var (
	ErrInvalid  = errors.New("invalid policy session journal")
	ErrReview   = errors.New("policy session journal requires review; no retry")
	ErrConflict = errors.New("policy session journal phase conflict")
	ErrExisting = errors.New("policy session evidence already exists")
	ErrBusy     = errors.New("policy session journal busy")
	ErrClosed   = errors.New("policy session journal closed")
	ErrPrivate  = policyevidence.ErrPrivate
)

type document struct {
	FormatTag     string `json:"format"`
	SchemaVersion int    `json:"schema_version"`
	Revision      uint64 `json:"revision"`
	Installation  string `json:"installation_id"`
	Opening       string `json:"opening"`
	Closure       string `json:"closure"`
}

func recordBytes(encoded string, empty bool) ([]byte, error) {
	if empty && encoded == "" {
		return nil, nil
	}
	if encoded == "" || len(encoded) > base64.StdEncoding.EncodedLen(policyevidence.MaxRecordBytes) {
		return nil, ErrInvalid
	}
	data, err := base64.StdEncoding.Strict().DecodeString(encoded)
	if err != nil || len(data) > policyevidence.MaxRecordBytes || base64.StdEncoding.EncodeToString(data) != encoded {
		clear(data)
		return nil, ErrInvalid
	}
	return data, nil
}
func (d document) observe(current policyevidence.Slot) (policyevidence.EpochDiagnosis, error) {
	o, err := recordBytes(d.Opening, false)
	if err != nil {
		return policyevidence.EpochDiagnosis{}, ErrInvalid
	}
	defer clear(o)
	c, err := recordBytes(d.Closure, d.Revision == 1)
	if err != nil {
		return policyevidence.EpochDiagnosis{}, ErrInvalid
	}
	defer clear(c)
	closure := policyevidence.Slot{State: policyevidence.Absent}
	if len(c) > 0 {
		closure = policyevidence.Slot{State: policyevidence.Present, Data: c}
	}
	result, err := policyevidence.MatchEpoch(d.Installation, policyevidence.Slot{State: policyevidence.Present, Data: o}, closure, current)
	if err != nil {
		return policyevidence.EpochDiagnosis{}, ErrInvalid
	}
	return result, nil
}
func (d document) validate() error {
	if d.FormatTag != documentFormat || d.SchemaVersion != 1 || (d.Revision != 1 && d.Revision != 2) || (d.Revision == 1) != (d.Closure == "") {
		return ErrInvalid
	}
	result, err := d.observe(policyevidence.Slot{})
	if err != nil || result.Kind() != policyevidence.IncompleteEpochEvidence {
		return ErrInvalid
	}
	return nil
}

// Supplied policy/history DATA only; the retained product root must supply the
// actual origins and full census. No diagnostic grants recovery or admission.
func (d document) observeHistory(checkpoint, current policyevidence.Slot, operations []policyevidence.HistoryOperation) (policyevidence.SessionDiagnosis, error) {
	return d.observeHistoryFor(d.Installation, checkpoint, current, operations)
}

func (d document) observeHistoryFor(installation string, checkpoint, current policyevidence.Slot, operations []policyevidence.HistoryOperation) (policyevidence.SessionDiagnosis, error) {
	o, err := recordBytes(d.Opening, false)
	if err != nil {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	defer clear(o)
	c, err := recordBytes(d.Closure, d.Revision == 1)
	if err != nil {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	defer clear(c)
	closure := policyevidence.Slot{State: policyevidence.Absent}
	if len(c) != 0 {
		closure = policyevidence.Slot{State: policyevidence.Present, Data: c}
	}
	diagnosis, err := policyevidence.MatchSessionHistory(installation, policyevidence.Slot{State: policyevidence.Present, Data: o}, closure, checkpoint, current, operations)
	if err != nil {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	return diagnosis, nil
}

// MatchObservedHistory decodes caller-supplied private journal DATA, then joins
// it with an independently expected installation and exact history/checkpoint.
// It performs no I/O, provenance/admission, initialization or recovery. Absent
// and unavailable documents stay distinct; neither means pristine. Every
// present input is validated before a diagnosis. Inputs stay immutable.
func MatchObservedHistory(installation string, journal, checkpoint, current policyevidence.Slot, operations []policyevidence.HistoryOperation) (policyevidence.SessionDiagnosis, error) {
	if len(operations) > policyevidence.MaxHistoryOperations || len(journal.Data) > maxDocumentBytes {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	if journal.State == policyevidence.Present {
		if len(journal.Data) == 0 {
			return policyevidence.SessionDiagnosis{}, ErrInvalid
		}
		d, err := decodeDocument(bytes.NewReader(journal.Data))
		if err != nil {
			return policyevidence.SessionDiagnosis{}, ErrInvalid
		}
		return d.observeHistoryFor(installation, checkpoint, current, operations)
	}
	if len(journal.Data) != 0 || journal.State != policyevidence.Absent && journal.State != policyevidence.Unavailable {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	empty := policyevidence.Slot{State: journal.State}
	d, err := policyevidence.MatchSessionHistory(installation, empty, empty, checkpoint, current, operations)
	if err != nil {
		return policyevidence.SessionDiagnosis{}, ErrInvalid
	}
	return d, nil
}
func decodeDocument(input io.Reader) (document, error) {
	if input == nil {
		return document{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(input, maxDocumentBytes+1))
	defer clear(data)
	if err != nil {
		return document{}, ErrInvalid
	}
	if _, err := configjson.DecodeEnvelope(data, maxDocumentBytes, 2, "format", "schema_version", "revision", "installation_id", "opening", "closure"); err != nil {
		return document{}, ErrInvalid
	}
	var d document
	if json.Unmarshal(data, &d) != nil || d.validate() != nil {
		return document{}, ErrInvalid
	}
	return d, nil
}
func (d document) MarshalJSON() ([]byte, error) {
	if d.validate() != nil {
		return nil, ErrInvalid
	}
	type wire document
	data, err := json.Marshal(wire(d))
	if err != nil || len(data) > maxDocumentBytes {
		return nil, ErrInvalid
	}
	return data, nil
}
func (document) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-session-document{private}")
}

// Canonical encoding is only for our own publications. Existing opening bytes
// stay base64-encoded exactly; semantic JSON rewriting cannot replace their hash.
func openingDocument(installation string, wire []byte) document {
	return document{documentFormat, 1, 1, installation, base64.StdEncoding.EncodeToString(wire), ""}
}
func sameWire(d document, wire []byte) bool {
	want, err := json.Marshal(d)
	defer clear(want)
	return err == nil && bytes.Equal(want, wire)
}
