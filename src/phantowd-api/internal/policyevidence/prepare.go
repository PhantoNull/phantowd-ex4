// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

var ErrPreparation = errors.New("policy operation preparation unavailable")

// Prepared retains private, immutable, caller-owned operation data, NOT an
// authority token. A future coordinator must first establish the base's retained
// origin, local confirmation, absence of unresolved work and consumer exclusion.
// Copies share immutable storage; all byte accessors return defensive copies.
// It generates no receipt and performs no filesystem, sync or recovery action.
type Prepared struct {
	base, candidate []byte
	intent          Intent
}

// Prepare preserves exact base bytes and encodes the coherent candidate using
// the current Store's encoding/json persistence contract. It checks all schema/
// revision/size constraints BEFORE allocating an operation ID internally with
// crypto/rand. No caller chooses an operation ID, digest or entropy provider.
// Inputs must remain stable during the call; no input references are retained.
// System entropy acquisition is not a context-cancellable I/O operation.
func Prepare(installation string, base []byte, next naspolicy.Config) (Prepared, error) {
	return prepare(installation, base, next, rand.Read)
}

// Private deterministic test seam, not an API/backend selector for operations.
func prepare(installation string, base []byte, next naspolicy.Config, entropy func([]byte) (int, error)) (Prepared, error) {
	if !canonicalHex(installation, 32, true) || len(base) == 0 || len(base) > naspolicy.MaxInputBytes {
		return Prepared{}, ErrInvalid
	}
	previous, err := naspolicy.Decode(bytes.NewReader(base))
	if err != nil || previous.Revision == math.MaxUint64 || next.Validate() != nil || next.Revision != previous.Revision+1 {
		return Prepared{}, ErrInvalid
	}
	candidate, err := json.Marshal(next)
	if err != nil || len(candidate) > naspolicy.MaxInputBytes {
		return Prepared{}, ErrInvalid
	}
	if _, err := naspolicy.Decode(bytes.NewReader(candidate)); err != nil {
		clear(candidate)
		return Prepared{}, ErrInvalid
	}
	var operation [16]byte
	if entropy == nil {
		clear(candidate)
		return Prepared{}, ErrPreparation
	}
	n, err := entropy(operation[:]) // one acquisition attempt, never retry a short/error result
	if err != nil || n != len(operation) {
		clear(operation[:])
		clear(candidate)
		return Prepared{}, ErrPreparation
	}
	baseHash, nextHash := sha256.Sum256(base), sha256.Sum256(candidate)
	i := Intent{value: tuple{installation, hex.EncodeToString(operation[:]), previous.Revision, next.Revision, hex.EncodeToString(baseHash[:]), hex.EncodeToString(nextHash[:])}}
	clear(operation[:])
	if !i.value.valid() {
		clear(candidate)
		return Prepared{}, ErrPreparation
	}
	return Prepared{base: bytes.Clone(base), candidate: candidate, intent: i}, nil
}

func (p Prepared) valid() bool {
	return len(p.base) > 0 && len(p.candidate) > 0 && p.intent.value.valid()
}
func (p Prepared) BaseBytes() ([]byte, error) {
	if !p.valid() {
		return nil, ErrInvalid
	}
	return bytes.Clone(p.base), nil
}
func (p Prepared) CandidateBytes() ([]byte, error) {
	if !p.valid() {
		return nil, ErrInvalid
	}
	return bytes.Clone(p.candidate), nil
}
func (p Prepared) Intent() (Intent, error) {
	if !p.valid() {
		return Intent{}, ErrInvalid
	}
	return p.intent, nil
}
func (Prepared) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "policy-operation-prepared{private}")
}
func (Prepared) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Prepared) UnmarshalJSON([]byte) error  { return ErrPrivate }
