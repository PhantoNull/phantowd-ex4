// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package identityprovision coordinates creation of one reserved native Unix
// identity. It has no privileged transport, credential or deletion API.
package identityprovision

import (
	"errors"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

const (
	Format         = "phantowd-identity-provision"
	MaxBytes       = 4096
	Reserved       = "reserved"
	GroupIntent    = "group-intent"
	GroupConfirmed = "group-confirmed"
	UserIntent     = "user-intent"
	UnixConfirmed  = "unix-confirmed"
	ReviewRequired = "review-required"
)

var (
	ErrInvalid     = errors.New("invalid identity provisioning journal")
	ErrConflict    = errors.New("identity provisioning revision conflict")
	ErrReview      = errors.New("identity provisioning requires explicit recovery review")
	ErrObservation = errors.New("identity provisioning observation unavailable")
)

type Journal struct {
	Format           string                  `json:"format"`
	SchemaVersion    int                     `json:"schema_version"`
	Revision         uint64                  `json:"revision"`
	RegistryRevision uint64                  `json:"registry_revision"`
	Account          serviceaccounts.Account `json:"account"`
	Phase            string                  `json:"phase"`
}

func (j Journal) Validate() error {
	r, err := serviceaccounts.New(j.Account.UID, j.Account.UID)
	r.Accounts = []serviceaccounts.Account{j.Account}
	if err != nil || r.Validate() != nil || j.Account.State != serviceaccounts.Disabled ||
		j.Format != Format || j.SchemaVersion != 1 || j.RegistryRevision == 0 {
		return ErrInvalid
	}
	// A journal has one monotonic operation, no resets, retries or compaction.
	valid := j.Phase == Reserved && j.Revision == 1 ||
		j.Phase == GroupIntent && j.Revision == 2 ||
		j.Phase == GroupConfirmed && j.Revision == 3 ||
		j.Phase == UserIntent && j.Revision == 4 ||
		j.Phase == UnixConfirmed && j.Revision == 5 ||
		j.Phase == ReviewRequired && j.Revision >= 2 && j.Revision <= 6
	if !valid {
		return ErrInvalid
	}
	return nil
}

func Decode(input io.Reader) (Journal, error) {
	var j Journal
	if input == nil || configjson.Decode(input, &j, MaxBytes, 4, map[string]bool{
		"format": true, "schema_version": true, "revision": true, "registry_revision": true,
		"account": true, "phase": true, "id": true, "name": true, "uid": true, "gid": true, "state": true,
	}) != nil || j.Validate() != nil {
		return Journal{}, ErrInvalid
	}
	return j, nil
}

func (j Journal) matches(r serviceaccounts.Registry) bool {
	if r.Validate() != nil || r.Revision != j.RegistryRevision {
		return false
	}
	for _, a := range r.Accounts {
		if a == j.Account {
			return true
		}
	}
	return false
}
