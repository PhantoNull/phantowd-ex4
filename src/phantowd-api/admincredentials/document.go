// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package admincredentials defines private, versioned panel credential state.
// It is not an authentication endpoint or an account recovery mechanism.
package admincredentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/passwordhash"
)

const (
	Version  = 2
	MaxBytes = 4096
)

var ErrInvalid = errors.New("invalid administrator credential document")

// Account contains a private verifier, never an HTTP response or log payload.
type Account struct {
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
}

type Document struct {
	Version  int     `json:"version"`
	Revision uint64  `json:"revision"`
	Admin    Account `json:"admin"`
}

// ValidUsername preserves the existing development enrollment grammar. Panel
// identities are distinct from Unix/Samba identities and imply no OS account.
func ValidUsername(name string) bool {
	if len(name) == 0 || len(name) > 32 {
		return false
	}
	for _, c := range name {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || strings.ContainsRune("._-", c)) {
			return false
		}
	}
	return true
}

func (d Document) Validate() error {
	if d.Version != Version || d.Revision == 0 || !ValidUsername(d.Admin.Username) ||
		passwordhash.ValidateVerifier(d.Admin.PasswordHash) != nil {
		return ErrInvalid
	}
	return nil
}

// Decode accepts only the exact compact encoding emitted by this package or
// the previous setup-only writer. Canonical equality rejects unknown, missing,
// duplicate, differently cased and null fields as well as trailing data.
// A valid v1 document is represented as revision 1 in memory; reading it does
// not rewrite the file. Only an explicit successful replacement publishes v2.
func Decode(r io.Reader) (Document, error) {
	var zero Document
	data, err := io.ReadAll(io.LimitReader(r, MaxBytes+1))
	if err != nil || len(data) == 0 || len(data) > MaxBytes {
		return zero, ErrInvalid
	}
	var header struct {
		Version int `json:"version"`
	}
	if json.Unmarshal(data, &header) != nil {
		return zero, ErrInvalid
	}
	var d Document
	var canonical []byte
	switch header.Version {
	case 1:
		var legacy struct {
			Version int     `json:"version"`
			Admin   Account `json:"admin"`
		}
		if json.Unmarshal(data, &legacy) != nil {
			return zero, ErrInvalid
		}
		canonical, err = json.Marshal(legacy)
		d = Document{Version: Version, Revision: 1, Admin: legacy.Admin}
	case Version:
		if json.Unmarshal(data, &d) != nil {
			return zero, ErrInvalid
		}
		canonical, err = json.Marshal(d)
	default:
		return zero, ErrInvalid
	}
	if err != nil || !bytes.Equal(canonical, data) || d.Validate() != nil {
		return zero, ErrInvalid
	}
	return d, nil
}
