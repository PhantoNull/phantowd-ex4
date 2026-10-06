// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package serviceaccounts owns desired file-service identities, not dashboard
// authentication or the live Unix/Samba databases. All planning is pure.
package serviceaccounts

import (
	"errors"
	"io"
	"math"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const (
	Format        = "phantowd-service-accounts"
	MaxInputBytes = 256 << 10
	MaxRecords    = 1024 // Includes permanent retired identities; never compact implicitly.
	MaxLive       = shareconfig.MaxUsers
	Disabled      = "disabled"
	Enabled       = "enabled"
	Retired       = "retired"
)

var (
	ErrInvalid    = errors.New("invalid service account registry")
	ErrConflict   = errors.New("service account revision conflict")
	ErrCollision  = errors.New("service account identity already reserved")
	ErrExhausted  = errors.New("service account identity capacity exhausted")
	ErrTransition = errors.New("invalid service account transition")
	ErrUnresolved = errors.New("share account identity is unresolved or disabled")
)

type Registry struct {
	Format        string    `json:"format"`
	SchemaVersion int       `json:"schema_version"`
	Revision      uint64    `json:"revision"`
	FirstID       uint32    `json:"first_id"`
	LastID        uint32    `json:"last_id"`
	Accounts      []Account `json:"accounts"`
}

// Each native account owns a same-number private primary group. Migration of
// existing/shared groups needs a separate explicit import model; no remapping.
type Account struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	UID   uint32 `json:"uid"`
	GID   uint32 `json:"gid"`
	State string `json:"state"`
}

// Reservations are caller-supplied exclusions, NOT an assertion of complete
// live discovery. The eventual privileged owner must inventory Unix identities,
// imported data ownership and other authorities and revalidate before applying.
// Nil collections are refused; an explicitly empty snapshot is allowed in tests.
type Reservations struct {
	UIDs  []uint32
	GIDs  []uint32
	Names []string
}

var fields = map[string]bool{
	"format": true, "schema_version": true, "revision": true, "first_id": true,
	"last_id": true, "accounts": true, "id": true, "name": true, "uid": true,
	"gid": true, "state": true,
}

func Decode(input io.Reader) (Registry, error) {
	var r Registry
	if configjson.Decode(input, &r, MaxInputBytes, 5, fields) != nil || r.Validate() != nil {
		return Registry{}, ErrInvalid
	}
	return r, nil
}

// New requires an explicit native allocation range; it selects no device or
// product default. IDs outside the native allocation window are excluded;
// callers must separately reserve system/imported identities inside that window.
func New(first, last uint32) (Registry, error) {
	r := Registry{Format: Format, SchemaVersion: 1, Revision: 1,
		FirstID: first, LastID: last, Accounts: []Account{}}
	return r, r.Validate()
}

func (r Registry) Validate() error {
	if r.Format != Format || r.SchemaVersion != 1 || r.Revision == 0 ||
		r.FirstID < 1000 || r.LastID > 60000 || r.FirstID > r.LastID ||
		r.Accounts == nil || len(r.Accounts) > MaxRecords {
		return ErrInvalid
	}
	ids, names, numbers := map[string]bool{}, map[string]bool{}, map[uint32]bool{}
	live := 0
	for _, a := range r.Accounts {
		if !validIdentity(a.ID, a.Name) || ids[a.ID] || names[a.Name] || numbers[a.UID] ||
			a.UID < r.FirstID || a.UID > r.LastID || a.GID != a.UID ||
			(a.State != Disabled && a.State != Enabled && a.State != Retired) {
			return ErrInvalid
		}
		ids[a.ID], names[a.Name], numbers[a.UID] = true, true, true
		if a.State != Retired {
			live++
		}
	}
	if live > MaxLive {
		return ErrInvalid
	}
	return nil
}

func validIdentity(id, name string) bool {
	// Share references and registry identities must use precisely the same
	// syntax/reserved-name rules; do not maintain a second account-name grammar.
	c := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{{ID: id, Name: name}}, Shares: []shareconfig.Share{}}
	return c.Validate() == nil
}

func (r Registry) next(expected uint64) (Registry, error) {
	if r.Validate() != nil {
		return Registry{}, ErrInvalid
	}
	if r.Revision != expected || expected == math.MaxUint64 {
		return Registry{}, ErrConflict
	}
	r.Accounts = append([]Account{}, r.Accounts...)
	r.Revision++
	return r, nil
}

// Create reserves the first available number in BOTH UID and GID namespaces.
// New identities always start disabled. Neither names nor IDs of retired
// accounts can be reused, even when no current share references them.
func (r Registry) Create(expected uint64, id, name string, reserved Reservations) (Registry, error) {
	next, err := r.next(expected)
	if err != nil {
		return Registry{}, err
	}
	if !validIdentity(id, name) || reserved.UIDs == nil || reserved.GIDs == nil || reserved.Names == nil ||
		len(reserved.UIDs) > 65536 || len(reserved.GIDs) > 65536 || len(reserved.Names) > 65536 {
		return Registry{}, ErrInvalid
	}
	used := map[uint32]bool{}
	for _, number := range reserved.UIDs {
		used[number] = true
	}
	for _, number := range reserved.GIDs {
		used[number] = true
	}
	for _, external := range reserved.Names {
		if len(external) == 0 || len(external) > 256 || !utf8.ValidString(external) || strings.ContainsAny(external, "\x00\r\n") {
			return Registry{}, ErrInvalid
		}
		if strings.EqualFold(external, name) {
			return Registry{}, ErrCollision
		}
	}
	live := 0
	for _, a := range r.Accounts {
		if a.ID == id || a.Name == name {
			return Registry{}, ErrCollision
		}
		used[a.UID] = true
		if a.State != Retired {
			live++
		}
	}
	if len(r.Accounts) >= MaxRecords || live >= MaxLive {
		return Registry{}, ErrExhausted
	}
	for candidate := r.FirstID; candidate <= r.LastID; candidate++ {
		if !used[candidate] {
			next.Accounts = append(next.Accounts, Account{ID: id, Name: name, UID: candidate, GID: candidate, State: Disabled})
			return next, nil
		}
	}
	return Registry{}, ErrExhausted
}

// SetState changes desired state only; it cannot claim passdb provisioning or
// live revocation. Retiring requires disabled desired state, keeps the record
// forever and is irreversible in this native-account API.
func (r Registry) SetState(expected uint64, id, state string) (Registry, error) {
	next, err := r.next(expected)
	if err != nil {
		return Registry{}, err
	}
	for i, a := range next.Accounts {
		if a.ID != id {
			continue
		}
		if a.State == Retired || a.State == state ||
			(state != Enabled && state != Disabled && state != Retired) ||
			(state == Retired && a.State != Disabled) {
			return Registry{}, ErrTransition
		}
		next.Accounts[i].State = state
		return next, nil
	}
	return Registry{}, ErrTransition
}

type Bindings struct {
	RegistryRevision uint64
	ShareRevision    uint64
	Accounts         []Account
}

// BindShares resolves every granted user by BOTH immutable project ID and
// exact name. Unused references do not grant access. The result is an intent
// binding, not proof of live Unix/passdb identity, permissions or ready mounts.
func (r Registry) BindShares(policy shareconfig.Config) (Bindings, error) {
	if r.Validate() != nil || policy.Validate() != nil {
		return Bindings{}, ErrInvalid
	}
	accounts, users := map[string]Account{}, map[string]string{}
	for _, a := range r.Accounts {
		accounts[a.ID] = a
	}
	for _, u := range policy.Users {
		users[u.ID] = u.Name
	}
	result := Bindings{RegistryRevision: r.Revision, ShareRevision: policy.Revision, Accounts: []Account{}}
	seen := map[string]bool{}
	for _, share := range policy.Shares {
		for _, grant := range share.Grants {
			a, ok := accounts[grant.UserID]
			if !ok || a.Name != users[grant.UserID] || a.State != Enabled {
				return Bindings{}, ErrUnresolved
			}
			if !seen[a.ID] {
				result.Accounts = append(result.Accounts, a)
				seen[a.ID] = true
			}
		}
	}
	slices.SortFunc(result.Accounts, func(a, b Account) int { return strings.Compare(a.ID, b.ID) })
	return result, nil
}
