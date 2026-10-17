// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

const epochOpeningFormat = "phantowd-policy-epoch-opening-experimental"
const epochClosureFormat = "phantowd-policy-epoch-closure-experimental"

// These private declarations are DATA, never a clean-shutdown, sync, provenance
// or boot-admission capability. There is no writer, opener or service here.
type EpochOpening struct{ value epochRecord }
type EpochClosure struct{ value epochRecord }
type epochRecord struct {
	Format         string `json:"format"`
	SchemaVersion  int    `json:"schema_version"`
	InstallationID string `json:"installation_id"`
	EpochID        string `json:"epoch_id"`
	Sequence       uint64 `json:"sequence"`
	OpeningSHA256  string `json:"opening_sha256,omitempty"`
	PolicyRevision uint64 `json:"policy_revision"`
	PolicySHA256   string `json:"policy_sha256"`
}

func (r epochRecord) valid(closure bool) bool {
	format := epochOpeningFormat
	if closure {
		format = epochClosureFormat
	}
	return r.Format == format && r.SchemaVersion == SchemaVersion && canonicalHex(r.InstallationID, 32, true) && canonicalHex(r.EpochID, 32, true) && r.Sequence > 0 && r.PolicyRevision > 0 && canonicalHex(r.PolicySHA256, 64, false) &&
		(closure && canonicalHex(r.OpeningSHA256, 64, false) || !closure && r.OpeningSHA256 == "")
}

func epochHash(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
func epochPolicy(data []byte) (uint64, string, error) {
	if len(data) == 0 || len(data) > naspolicy.MaxInputBytes {
		return 0, "", ErrInvalid
	}
	c, err := naspolicy.Decode(bytes.NewReader(data))
	if err != nil {
		return 0, "", ErrInvalid
	}
	return c.Revision, epochHash(data), nil
}

// Caller-supplied IDs describe a proposed declaration only. A future trusted
// coordinator must allocate and retain its own epoch, not accept one over HTTP.
func DeclareEpochOpening(installation, epoch string, sequence uint64, policy []byte) (EpochOpening, error) {
	revision, digest, err := epochPolicy(policy)
	if err != nil {
		return EpochOpening{}, ErrInvalid
	}
	r := epochRecord{Format: epochOpeningFormat, SchemaVersion: SchemaVersion, InstallationID: installation, EpochID: epoch, Sequence: sequence, PolicyRevision: revision, PolicySHA256: digest}
	if !r.valid(false) {
		return EpochOpening{}, ErrInvalid
	}
	return EpochOpening{r}, nil
}

// Declaring closure performs NO close, drain, synchronization or confirmation.
// Its exact opening-byte binding must later be checked against retained origin
// and the complete operation/consumer state. A declaration is not proof of them.
func DeclareEpochClosure(opening, policy []byte) (EpochClosure, error) {
	o, err := DecodeEpochOpening(bytes.NewReader(opening))
	if err != nil {
		return EpochClosure{}, ErrInvalid
	}
	revision, digest, err := epochPolicy(policy)
	if err != nil || revision < o.value.PolicyRevision || revision == o.value.PolicyRevision && digest != o.value.PolicySHA256 {
		return EpochClosure{}, ErrInvalid
	}
	r := o.value
	r.Format = epochClosureFormat
	r.OpeningSHA256 = epochHash(opening)
	r.PolicyRevision, r.PolicySHA256 = revision, digest
	return EpochClosure{r}, nil
}

func decodeEpoch(input io.Reader, closure bool) (epochRecord, error) {
	if input == nil {
		return epochRecord{}, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(input, MaxRecordBytes+1))
	if err != nil {
		return epochRecord{}, ErrInvalid
	}
	defer clear(data)
	keys := []string{"format", "schema_version", "installation_id", "epoch_id", "sequence", "policy_revision", "policy_sha256"}
	if closure {
		keys = append(keys, "opening_sha256")
	}
	if _, err := configjson.DecodeEnvelope(data, MaxRecordBytes, 2, keys...); err != nil {
		return epochRecord{}, ErrInvalid
	}
	var r epochRecord
	if json.Unmarshal(data, &r) != nil || !r.valid(closure) {
		return epochRecord{}, ErrInvalid
	}
	return r, nil
}
func DecodeEpochOpening(input io.Reader) (EpochOpening, error) {
	r, err := decodeEpoch(input, false)
	if err != nil {
		return EpochOpening{}, err
	}
	return EpochOpening{r}, nil
}
func DecodeEpochClosure(input io.Reader) (EpochClosure, error) {
	r, err := decodeEpoch(input, true)
	if err != nil {
		return EpochClosure{}, err
	}
	return EpochClosure{r}, nil
}
func EncodeEpochOpening(r EpochOpening) ([]byte, error) {
	if !r.value.valid(false) {
		return nil, ErrInvalid
	}
	return json.Marshal(r.value)
}
func EncodeEpochClosure(r EpochClosure) ([]byte, error) {
	if !r.value.valid(true) {
		return nil, ErrInvalid
	}
	return json.Marshal(r.value)
}

type EpochKind string

const (
	NoEpochRecorded           EpochKind = "no-epoch-recorded"
	OpenEpochObserved         EpochKind = "open-epoch-observed"
	ClosureMatchesCurrent     EpochKind = "closure-matches-current"
	InconsistentEpochEvidence EpochKind = "inconsistent-epoch-evidence"
	IncompleteEpochEvidence   EpochKind = "incomplete-epoch-evidence"
)

type EpochDiagnosis struct{ kind EpochKind }

func (d EpochDiagnosis) Kind() EpochKind { return d.kind }

// MatchEpoch compares supplied private DATA, not filesystem/boot provenance.
// Validate all present records before classifying missing inputs. Even matching
// declarations cannot prove past successful fsync/Close, absence of consumers,
// complete history/roles, power-loss durability or protection against rollback.
func MatchEpoch(installation string, opening, closing, current Slot) (EpochDiagnosis, error) {
	if !canonicalHex(installation, 32, true) || !opening.valid() || !closing.valid() || !current.valid() || len(opening.Data) > MaxRecordBytes || len(closing.Data) > MaxRecordBytes || len(current.Data) > naspolicy.MaxInputBytes {
		return EpochDiagnosis{}, ErrInvalid
	}
	var o, c epochRecord
	var revision uint64
	var digest string
	if opening.State == Present {
		v, err := DecodeEpochOpening(bytes.NewReader(opening.Data))
		if err != nil {
			return EpochDiagnosis{}, ErrInvalid
		}
		o = v.value
	}
	if closing.State == Present {
		v, err := DecodeEpochClosure(bytes.NewReader(closing.Data))
		if err != nil {
			return EpochDiagnosis{}, ErrInvalid
		}
		c = v.value
	}
	if current.State == Present {
		var err error
		revision, digest, err = epochPolicy(current.Data)
		if err != nil {
			return EpochDiagnosis{}, ErrInvalid
		}
	}
	inconsistent := opening.State == Present && o.InstallationID != installation || closing.State == Present && c.InstallationID != installation || closing.State == Present && opening.State == Absent
	if opening.State == Present && closing.State == Present {
		inconsistent = inconsistent || o.EpochID != c.EpochID || o.Sequence != c.Sequence || c.OpeningSHA256 != epochHash(opening.Data) || c.PolicyRevision < o.PolicyRevision || c.PolicyRevision == o.PolicyRevision && c.PolicySHA256 != o.PolicySHA256
	}
	if current.State == Present {
		inconsistent = inconsistent || closing.State == Present && (c.PolicyRevision != revision || c.PolicySHA256 != digest) ||
			opening.State == Present && (revision < o.PolicyRevision || revision == o.PolicyRevision && digest != o.PolicySHA256)
	}
	if inconsistent {
		return EpochDiagnosis{InconsistentEpochEvidence}, nil
	}
	if opening.State == Unavailable || closing.State == Unavailable || current.State != Present {
		return EpochDiagnosis{IncompleteEpochEvidence}, nil
	}
	if closing.State == Present {
		return EpochDiagnosis{ClosureMatchesCurrent}, nil
	}
	if opening.State == Present {
		return EpochDiagnosis{OpenEpochObserved}, nil
	}
	return EpochDiagnosis{NoEpochRecorded}, nil
}

func (EpochOpening) MarshalJSON() ([]byte, error)   { return nil, ErrPrivate }
func (EpochClosure) MarshalJSON() ([]byte, error)   { return nil, ErrPrivate }
func (EpochDiagnosis) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*EpochOpening) UnmarshalJSON([]byte) error    { return ErrPrivate }
func (*EpochClosure) UnmarshalJSON([]byte) error    { return ErrPrivate }
func (*EpochDiagnosis) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (EpochOpening) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-epoch-opening{private}")
}
func (EpochClosure) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-epoch-closure{private}")
}
func (d EpochDiagnosis) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-epoch-diagnosis{"+string(d.kind)+"}")
}
