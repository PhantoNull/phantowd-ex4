// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package smbprovision is an internal journal for enrolling one already-
// provisioned native identity into Samba. It never enables accounts or persists
// credentials.
package smbprovision

import (
	"errors"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

const (
	Format                = "phantowd-smb-provision"
	MaxBytes              = 4096
	Reserved              = "reserved"
	CreateIntent          = "create-disabled-intent"
	DisabledNoPassword    = "disabled-no-password"
	PasswordIntent        = "set-password-disabled-intent"
	CredentialSetDisabled = "credential-set-disabled"
	ReviewRequired        = "review-required"
	MinPasswordBytes      = 12
	MaxPasswordBytes      = 256
)

var (
	ErrInvalid     = errors.New("invalid Samba enrollment journal or request")
	ErrConflict    = errors.New("Samba enrollment revision conflict")
	ErrReview      = errors.New("Samba enrollment requires explicit recovery review")
	ErrObservation = errors.New("Samba account observation unavailable or mismatched")
	ErrPending     = errors.New("Samba enrollment is incomplete")
)

// Journal contains only stable identity and observed passdb metadata. It must
// never contain a password, NT/LM hash, command output or password-derived data.
type Journal struct {
	Format         string                  `json:"format"`
	SchemaVersion  int                     `json:"schema_version"`
	Revision       uint64                  `json:"revision"`
	NativeRevision uint64                  `json:"native_revision"`
	Account        serviceaccounts.Account `json:"account"`
	SID            string                  `json:"sid,omitempty"`
	Phase          string                  `json:"phase"`
}

// Observation is a redacted passdb view. SID is the only Samba identity value
// retained; password hashes and authentication material are never exposed.
type Observation struct {
	Present  bool
	Name     string
	UID      uint32
	GID      uint32
	SID      string
	Disabled bool
}

func (o Observation) validateFor(a serviceaccounts.Account, requireDisabled bool) error {
	if !o.Present {
		if o.Name != "" || o.UID != 0 || o.GID != 0 || o.SID != "" || o.Disabled {
			return ErrObservation
		}
		return nil
	}
	if o.Name != a.Name || o.UID != a.UID || o.GID != a.GID || !validSID(o.SID) ||
		(requireDisabled && !o.Disabled) {
		return ErrObservation
	}
	return nil
}

func validSID(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 8 || parts[0] != "S" || parts[1] != "1" || parts[2] != "5" || parts[3] != "21" {
		return false
	}
	for _, part := range parts[4:] {
		n, err := strconv.ParseUint(part, 10, 32)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != part {
			return false
		}
	}
	return true
}

func (j Journal) Validate() error {
	r, err := serviceaccounts.New(j.Account.UID, j.Account.UID)
	r.Accounts = []serviceaccounts.Account{j.Account}
	if err != nil || r.Validate() != nil || j.Account.State != serviceaccounts.Disabled ||
		j.Format != Format || j.SchemaVersion != 1 || j.Revision == 0 || j.NativeRevision == 0 {
		return ErrInvalid
	}
	validPhase := j.Phase == Reserved && j.Revision == 1 ||
		j.Phase == CreateIntent && j.Revision == 2 ||
		j.Phase == DisabledNoPassword && j.Revision == 3 ||
		j.Phase == PasswordIntent && j.Revision == 4 ||
		j.Phase == CredentialSetDisabled && j.Revision == 5 ||
		j.Phase == ReviewRequired && j.Revision >= 2 && j.Revision <= 6
	requireSID := sidRequired(j.Phase) || j.Phase == ReviewRequired && j.Revision >= 4
	validReviewSID := j.Phase == ReviewRequired && j.Revision == 3 && j.SID != "" && validSID(j.SID)
	if !validPhase || !requireSID && j.SID != "" && !validReviewSID ||
		requireSID && !validSID(j.SID) {
		return ErrInvalid
	}
	return nil
}

func sidRequired(phase string) bool {
	return phase == DisabledNoPassword || phase == PasswordIntent ||
		phase == CredentialSetDisabled
}

func Decode(input io.Reader) (Journal, error) {
	var j Journal
	if input == nil || configjson.Decode(input, &j, MaxBytes, 5, map[string]bool{
		"format": true, "schema_version": true, "revision": true,
		"native_revision": true, "account": true, "id": true, "name": true,
		"uid": true, "gid": true, "state": true, "sid": true, "phase": true,
	}) != nil || j.Validate() != nil {
		return Journal{}, ErrInvalid
	}
	return j, nil
}

// ValidPassword accepts only secrets that can be transported unambiguously as
// two smbpasswd stdin lines. Callers must not persist or log the input.
func ValidPassword(secret []byte) bool {
	if len(secret) < MinPasswordBytes || len(secret) > MaxPasswordBytes || !utf8.Valid(secret) {
		return false
	}
	for remaining := secret; len(remaining) > 0; {
		r, size := utf8.DecodeRune(remaining)
		if unicode.IsControl(r) {
			return false
		}
		remaining = remaining[size:]
	}
	return true
}
