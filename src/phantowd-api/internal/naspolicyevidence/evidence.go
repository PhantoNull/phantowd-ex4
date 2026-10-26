// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package naspolicyevidence compares private records with exact NAS policy bytes.
// Every result is diagnostic only: no admission, replay or historical fsync proof.
package naspolicyevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

const (
	IntentFormat   = "phantowd-nas-policy-intent"
	ReceiptFormat  = "phantowd-nas-policy-local-receipt"
	MaxRecordBytes = 4096
)

type Kind uint8

const (
	Unavailable   Kind = iota
	InvalidPolicy      // Combined invalid/unsupported diagnostic, never migration.
	NoRecordedOperation
	UnconfirmedBase
	UnconfirmedPublication
	MatchingLocalRecords
	Inconsistent
)

type record struct {
	Format         string `json:"format"`
	SchemaVersion  int    `json:"schema_version"`
	InstallationID string `json:"installation_id"`
	OperationID    string `json:"operation_id"`
	BaseRevision   uint64 `json:"base_revision"`
	NextRevision   uint64 `json:"next_revision"`
	BaseSHA256     string `json:"base_sha256"`
	NextSHA256     string `json:"next_sha256"`
	Phase          string `json:"phase,omitempty"`
}

var errInvalid = errors.New("invalid NAS operation evidence")

func decode(data []byte, receipt bool) (record, error) {
	keys := []string{"format", "schema_version", "installation_id", "operation_id", "base_revision", "next_revision", "base_sha256", "next_sha256"}
	format, phase := IntentFormat, ""
	if receipt {
		keys = append(keys, "phase")
		format, phase = ReceiptFormat, "local-confirmed"
	}
	_, err := configjson.DecodeEnvelope(data, MaxRecordBytes, 2, keys...)
	var r record
	if err != nil || json.Unmarshal(data, &r) != nil || r.Format != format || r.SchemaVersion != 1 || r.Phase != phase ||
		!canonicalHex(r.InstallationID, 32, true) || !canonicalHex(r.OperationID, 32, true) ||
		r.BaseRevision == 0 || r.BaseRevision == math.MaxUint64 || r.NextRevision != r.BaseRevision+1 ||
		!canonicalHex(r.BaseSHA256, 64, false) || !canonicalHex(r.NextSHA256, 64, false) {
		return record{}, errInvalid
	}
	return r, nil
}

func canonicalHex(s string, size int, nonzero bool) bool {
	if len(s) != size {
		return false
	}
	seen := false
	for _, c := range s {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
		seen = seen || c != '0'
	}
	return !nonzero || seen
}

// Inspect consumes complete caller-owned observations; nil records mean absent,
// not unreadable. The trusted caller asserts completeness, not file provenance.
// Do not mutate input concurrently. No IDs, digests or input bytes are returned.
func Inspect(installationID string, current, intent, receipt []byte, complete bool) Kind {
	if !complete || current == nil || !canonicalHex(installationID, 32, true) {
		return Unavailable
	}
	policy, err := naspolicy.Decode(bytes.NewReader(current))
	if err != nil {
		return InvalidPolicy
	}
	if intent == nil {
		if receipt == nil {
			return NoRecordedOperation
		}
		return Inconsistent
	}
	i, err := decode(intent, false)
	if err != nil || i.InstallationID != installationID {
		return Inconsistent
	}
	digest := sha256.Sum256(current)
	hash := hex.EncodeToString(digest[:])
	base := policy.Revision == i.BaseRevision && hash == i.BaseSHA256
	next := policy.Revision == i.NextRevision && hash == i.NextSHA256
	if receipt == nil {
		if base {
			return UnconfirmedBase
		}
		if next {
			return UnconfirmedPublication
		}
		return Inconsistent
	}
	r, err := decode(receipt, true)
	if err != nil {
		return Inconsistent
	}
	r.Format, r.Phase = i.Format, ""
	if r == i && next {
		return MatchingLocalRecords
	}
	return Inconsistent
}
