// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

func addManagementAccounts(t *testing.T, identity *IdentitySnapshot) {
	t.Helper()
	for index, state := range []string{serviceaccounts.Disabled, serviceaccounts.Enabled, serviceaccounts.Retired} {
		account := serviceaccounts.Account{ID: []string{"pending", "ungranted", "retired"}[index],
			Name: []string{"bob", "carol", "dave"}[index], UID: uint32(1001 + index), GID: uint32(1001 + index), State: state}
		identity.Registry.Accounts = append(identity.Registry.Accounts, account)
		if state != serviceaccounts.Retired {
			identity.UnixUIDs = append(identity.UnixUIDs, account.UID)
			identity.UnixGIDs = append(identity.UnixGIDs, account.GID)
		}
	}
}

func TestSambaRoleCandidateKeepsManagementAndGrantedViewsSeparate(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	addManagementAccounts(t, &identity)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	roles, err := plan.SambaRoleCandidate()
	if err != nil || !roles.FreshAgainst(plan.Freshness()) {
		t.Fatal("same-Plan role candidate refused", err)
	}
	passwd, group, nss, err := roles.ManagementDocuments()
	if err != nil || !unixidentity.FilesOnlyNSS([]byte(nss)) || len(passwd)+len(group)+len(nss) > MaxSambaNSSBytes {
		t.Fatal("management documents lost their grammar or budget", err)
	}
	lookup, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range identity.Registry.Accounts[:3] {
		if status, err := lookup.Assess(account); err != nil || status != unixidentity.Observed {
			t.Fatal("management omitted a live identity", err)
		}
	}
	service, err := roles.ServiceCandidate()
	if err != nil {
		t.Fatal(err)
	}
	sp, sg, sn, sections, roots, err := service.Documents()
	ep, eg, en, _ := plan.SambaNSSCandidates()
	if err != nil || sp != ep || sg != eg || sn != en || len(roots) != 1 ||
		!strings.Contains(sections, "write list = alice") {
		t.Fatal("role packaging changed grants or source requests", err)
	}
	for _, name := range []string{"bob", "carol", "dave"} {
		if strings.Contains(sp, name+":") || strings.Contains(sg, name+":") || strings.Contains(sections, name) {
			t.Fatal("management identity broadened service access", name)
		}
	}
	if strings.Contains(passwd, "dave:") || strings.Contains(group, "dave:") || len(identity.Registry.Accounts) != 4 {
		t.Fatal("retired lookup row admitted or reservation discarded")
	}
	// Returned strings and root slices, and subsequent caller mutation, cannot
	// turn the management roster into a different service candidate.
	roots[0].RelativePath = "replacement"
	identity.Registry.Accounts[0].Name = "replacement"
	identity.UnixUIDs[0]++
	config.Shares.Shares[0].Grants[0].Access = "ro"
	actual, _, _, _ := roles.ManagementDocuments()
	_, _, _, actualSections, actualRoots, _ := service.Documents()
	if actual != passwd || actualSections != sections || actualRoots[0].RelativePath == "replacement" {
		t.Fatal("role candidate aliases mutable caller input")
	}
	for name, mutate := range map[string]func(*Freshness){
		"policy":               func(f *Freshness) { f.PolicyRevision++ },
		"active":               func(f *Freshness) { f.ActiveRevision++ },
		"identity generation":  func(f *Freshness) { f.IdentityGeneration++ },
		"identity fingerprint": func(f *Freshness) { f.IdentityFingerprint[0] ^= 1 },
		"storage generation":   func(f *Freshness) { f.StorageGeneration++ },
		"storage fingerprint":  func(f *Freshness) { f.StorageFingerprint[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := plan.Freshness()
			mutate(&changed)
			if roles.FreshAgainst(changed) || service.FreshAgainst(changed) {
				t.Fatal("either role remained fresh against changed evidence")
			}
		})
	}
	if _, err := json.Marshal(roles); err == nil {
		t.Fatal("internal role candidate crossed JSON boundary")
	}
	var decoded SambaRoleCandidate
	if json.Unmarshal([]byte(`{}`), &decoded) == nil {
		t.Fatal("JSON supplied a two-role candidate")
	}
}

func TestSambaRoleCandidateRefusesIncompleteManagementWithoutChangingSharePlan(t *testing.T) {
	for _, dimension := range []string{"uid", "gid"} {
		t.Run(dimension, func(t *testing.T) {
			config, active, identity, storage := planInputs(t)
			addManagementAccounts(t, &identity)
			if dimension == "uid" {
				identity.UnixUIDs = identity.UnixUIDs[:1]
			} else {
				identity.UnixGIDs = identity.UnixGIDs[:1]
			}
			plan, err := Build(config, active, identity, storage)
			if err != nil {
				t.Fatal("unrelated missing identity changed existing share-only admission", err)
			}
			if _, err := plan.SambaIsolatedCandidate(); err != nil {
				t.Fatal("valid existing share candidate lost", err)
			}
			roles, err := plan.SambaRoleCandidate()
			if !errors.Is(err, ErrNotReady) {
				t.Fatal("incomplete management roster yielded role candidate", err)
			}
			assertNoSambaRoles(t, roles)
		})
	}
}

func assertNoSambaRoles(t *testing.T, roles SambaRoleCandidate) {
	t.Helper()
	passwd, group, nss, err := roles.ManagementDocuments()
	if !errors.Is(err, ErrNotReady) || passwd != "" || group != "" || nss != "" || roles.FreshAgainst(Freshness{}) {
		t.Fatal("refused role candidate exposed partial management documents")
	}
	service, err := roles.ServiceCandidate()
	if !errors.Is(err, ErrNotReady) || service.FreshAgainst(Freshness{}) {
		t.Fatal("refused role candidate exposed usable service view")
	}
}

func TestSambaRoleCandidateRefusesZeroNFSOnlyAndWholeVolumePlans(t *testing.T) {
	assertNoSambaRoles(t, SambaRoleCandidate{})
	if roles, err := (Plan{}).SambaRoleCandidate(); !errors.Is(err, ErrNotReady) {
		t.Fatal("zero Plan admitted roles")
	} else {
		assertNoSambaRoles(t, roles)
	}
	for _, whole := range []bool{false, true} {
		config, active, identity, storage := planInputs(t)
		if whole {
			config.Shares.Shares[0].RelativePath = "."
		} else {
			config.Shares.Shares = []shareconfig.Share{}
		}
		plan, err := Build(config, active, identity, storage)
		if err != nil {
			t.Fatal(err)
		}
		roles, err := plan.SambaRoleCandidate()
		if !errors.Is(err, ErrNotReady) {
			t.Fatal("unsupported service view admitted roles", err)
		}
		assertNoSambaRoles(t, roles)
	}
}

func TestSambaRoleCandidateManagementOrderIsDeterministic(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	addManagementAccounts(t, &identity)
	first, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	roles, _ := first.SambaRoleCandidate()
	passwd, group, nss, _ := roles.ManagementDocuments()
	slices.Reverse(identity.Registry.Accounts)
	slices.Reverse(identity.UnixUIDs)
	slices.Reverse(identity.UnixGIDs)
	second, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	other, err := second.SambaRoleCandidate()
	op, og, on, docsErr := other.ManagementDocuments()
	if err != nil || docsErr != nil || op != passwd || og != group || on != nss {
		t.Fatal("management output depends on evidence enumeration order")
	}
}

func TestSambaRoleCandidateBoundsLiveManagementWithoutDiscardingRetiredReservations(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	identity.Registry.LastID = 3000
	for index := 1; index < serviceaccounts.MaxRecords; index++ {
		state := serviceaccounts.Retired
		if index < serviceaccounts.MaxLive {
			state = serviceaccounts.Disabled
		}
		account := serviceaccounts.Account{ID: fmt.Sprintf("u%d", index), Name: fmt.Sprintf("u%031d", index),
			UID: uint32(1000 + index), GID: uint32(1000 + index), State: state}
		identity.Registry.Accounts = append(identity.Registry.Accounts, account)
		if state != serviceaccounts.Retired {
			identity.UnixUIDs = append(identity.UnixUIDs, account.UID)
			identity.UnixGIDs = append(identity.UnixGIDs, account.GID)
		}
	}
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal("maximum valid native registry refused", err)
	}
	roles, err := plan.SambaRoleCandidate()
	if err != nil {
		t.Fatal("maximum live management roster refused", err)
	}
	passwd, group, nss, err := roles.ManagementDocuments()
	if err != nil || len(passwd)+len(group)+len(nss) > MaxSambaNSSBytes ||
		strings.Count(passwd, "\n") != serviceaccounts.MaxLive+2 || strings.Count(group, "\n") != serviceaccounts.MaxLive+2 ||
		len(identity.Registry.Accounts) != serviceaccounts.MaxRecords {
		t.Fatal("maximum management roster lost its live bound or permanent reservations", err)
	}
	lookup, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		t.Fatal(err)
	}
	for _, account := range identity.Registry.Accounts[:serviceaccounts.MaxLive] {
		if status, err := lookup.Assess(account); err != nil || status != unixidentity.Observed {
			t.Fatal("bounded management lookup lost private identity", err)
		}
	}
	service, err := roles.ServiceCandidate()
	if err != nil {
		t.Fatal(err)
	}
	sp, sg, _, _, _, err := service.Documents()
	if err != nil || strings.Count(sp, "\n") != 3 || strings.Count(sg, "\n") != 3 {
		t.Fatal("maximum management roster broadened the one-account service lookup", err)
	}
}
