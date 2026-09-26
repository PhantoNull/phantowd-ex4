// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package unixidentity observes supplied local passwd/group documents. It does
// not query NSS, read shadow, adopt identities or authorize account mutations.
package unixidentity

import (
	"errors"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

const (
	MaxFileBytes = 1 << 20
	MaxRecords   = 4096
	MaxLineBytes = 16384
	Absent       = "absent-from-supplied-files"
	Partial      = "partial-local-identity"
	Conflict     = "conflicting-local-identity"
	Observed     = "matching-local-identity"
)

var ErrInvalid = errors.New("invalid or incomplete local identity documents")

type user struct {
	name     string
	uid, gid uint32
}
type group struct {
	name    string
	gid     uint32
	members []string
}

// Snapshot is immutable after successful Parse; zero values are not observations.
// Password/GECOS/home/shell values are not retained or exposed. The snapshot
// proves neither file provenance nor that both inputs were captured atomically.
type Snapshot struct {
	valid  bool
	users  []user
	groups []group
}

func Parse(passwd, groups io.Reader) (Snapshot, error) {
	var result Snapshot
	rows, err := readRows(passwd, 7)
	if err != nil {
		return Snapshot{}, ErrInvalid
	}
	for _, fields := range rows {
		uid, e1 := number(fields[2])
		gid, e2 := number(fields[3])
		if e1 != nil || e2 != nil {
			return Snapshot{}, ErrInvalid
		}
		// Clone retained strings so a name cannot retain the entire input,
		// including password fields, through a shared string backing array.
		result.users = append(result.users, user{strings.Clone(fields[0]), uid, gid})
	}
	rows, err = readRows(groups, 4)
	if err != nil {
		return Snapshot{}, ErrInvalid
	}
	for _, fields := range rows {
		gid, err := number(fields[2])
		if err != nil {
			return Snapshot{}, ErrInvalid
		}
		g := group{name: strings.Clone(fields[0]), gid: gid, members: []string{}}
		seen := map[string]bool{}
		if fields[3] != "" {
			for _, member := range strings.Split(fields[3], ",") {
				if !name(member) || seen[member] {
					return Snapshot{}, ErrInvalid
				}
				seen[member] = true
				g.members = append(g.members, strings.Clone(member))
			}
		}
		result.groups = append(result.groups, g)
	}
	result.valid = true
	return result, nil
}

func readRows(input io.Reader, count int) ([][]string, error) {
	if input == nil {
		return nil, ErrInvalid
	}
	data, err := io.ReadAll(io.LimitReader(input, MaxFileBytes+1))
	if err != nil || len(data) > MaxFileBytes || !utf8.Valid(data) {
		return nil, ErrInvalid
	}
	for _, c := range data {
		if c != '\n' && (c < 32 || c == 127) {
			return nil, ErrInvalid
		}
	}
	rows := [][]string{}
	seen := map[string]bool{}
	for _, line := range strings.Split(string(data), "\n") {
		if len(line) > MaxLineBytes {
			return nil, ErrInvalid
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, ":")
		if len(fields) != count || !name(fields[0]) || seen[fields[0]] || len(rows) >= MaxRecords {
			return nil, ErrInvalid
		}
		seen[fields[0]] = true
		rows = append(rows, fields)
	}
	if len(rows) == 0 {
		return nil, ErrInvalid
	}
	return rows, nil
}

func name(value string) bool {
	if len(value) == 0 || len(value) > 256 {
		return false
	}
	for _, c := range value {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.' || c == '$') {
			return false
		}
	}
	return true
}

func number(value string) (uint32, error) {
	if value == "" || len(value) > 10 {
		return 0, ErrInvalid
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			return 0, ErrInvalid
		}
	}
	n, err := strconv.ParseUint(value, 10, 32)
	if err != nil || n == math.MaxUint32 {
		return 0, ErrInvalid
	}
	return uint32(n), nil
}

// Reservations returns independent sorted exclusions from these files only.
// Primary GIDs with no group row and orphan group-member names also reserve
// identities. Imported file ownership and remote NSS remain caller obligations.
func (s Snapshot) Reservations() (serviceaccounts.Reservations, error) {
	if !s.valid {
		return serviceaccounts.Reservations{}, ErrInvalid
	}
	uids, gids, names := map[uint32]bool{}, map[uint32]bool{}, map[string]bool{}
	for _, u := range s.users {
		uids[u.uid] = true
		gids[u.gid] = true
		names[u.name] = true
	}
	for _, g := range s.groups {
		gids[g.gid] = true
		names[g.name] = true
		for _, m := range g.members {
			names[m] = true
		}
	}
	r := serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}
	for n := range uids {
		r.UIDs = append(r.UIDs, n)
	}
	for n := range gids {
		r.GIDs = append(r.GIDs, n)
	}
	for n := range names {
		r.Names = append(r.Names, n)
	}
	// The registry's limit is also enforced before returning an observation.
	if len(r.Names) > 65536 {
		return serviceaccounts.Reservations{}, ErrInvalid
	}
	slices.Sort(r.UIDs)
	slices.Sort(r.GIDs)
	slices.Sort(r.Names)
	return r, nil
}

// Assess compares a native private-group identity, independent of desired
// enabled/disabled state. Even Observed is not ownership/adoption, password,
// login-lock or authorization evidence. Partial/Conflict never imply repair.
func (s Snapshot) Assess(a serviceaccounts.Account) (string, error) {
	r, err := serviceaccounts.New(a.UID, a.UID)
	r.Accounts = []serviceaccounts.Account{a}
	if !s.valid || err != nil || r.Validate() != nil {
		return "", ErrInvalid
	}
	hasUser, hasGroup := false, false
	for _, u := range s.users {
		if strings.EqualFold(u.name, a.Name) {
			if u.name != a.Name || u.uid != a.UID || u.gid != a.GID {
				return Conflict, nil
			}
			hasUser = true
		} else if u.uid == a.UID || u.gid == a.GID {
			return Conflict, nil
		}
	}
	for _, g := range s.groups {
		own := g.name == a.Name && g.gid == a.GID
		if strings.EqualFold(g.name, a.Name) || g.gid == a.GID {
			if !own {
				return Conflict, nil
			}
			hasGroup = true
		}
		for _, m := range g.members {
			if own && m != a.Name || !own && strings.EqualFold(m, a.Name) {
				return Conflict, nil
			}
		}
	}
	if hasUser && hasGroup {
		return Observed, nil
	}
	if hasUser || hasGroup {
		return Partial, nil
	}
	return Absent, nil
}
