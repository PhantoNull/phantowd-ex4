// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestIsolatedSambaCandidateBindsAllDocumentsAndFreshness(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.SambaIsolatedCandidate()
	if err != nil {
		t.Fatal(err)
	}
	passwd, group, nss, sections, roots, err := candidate.Documents()
	expectedPasswd, expectedGroup, expectedNSS, lookupErr := plan.SambaNSSCandidates()
	expectedSections, expectedRoots, shareErr := plan.SambaShareCandidates()
	if err != nil || lookupErr != nil || shareErr != nil || passwd != expectedPasswd || group != expectedGroup ||
		nss != expectedNSS || sections != expectedSections || !reflect.DeepEqual(roots, expectedRoots) ||
		!candidate.FreshAgainst(plan.Freshness()) || strings.Contains(sections, "/run/phantowd/volumes/") {
		t.Fatal("isolated candidate lost complete plan lookup/grants/root/freshness binding")
	}
	// Neither mutable policy nor caller-owned descriptor requests can change the
	// immutable candidate. Strings are values, not writable staging authority.
	config.Shares.Shares[0].Grants[0].Access = "ro"
	roots[0].RelativePath, roots[0].ReadOnly = "replacement", true
	_, _, _, afterSections, afterRoots, err := candidate.Documents()
	if err != nil || afterSections != sections || !reflect.DeepEqual(afterRoots, expectedRoots) {
		t.Fatal("candidate aliases caller data")
	}
	for name, mutate := range map[string]func(*Freshness){
		"policy":               func(f *Freshness) { f.PolicyRevision++ },
		"active":               func(f *Freshness) { f.ActiveRevision++ },
		"identity generation":  func(f *Freshness) { f.IdentityGeneration++ },
		"identity observation": func(f *Freshness) { f.IdentityFingerprint[0] ^= 1 },
		"storage generation":   func(f *Freshness) { f.StorageGeneration++ },
		"storage observation":  func(f *Freshness) { f.StorageFingerprint[0] ^= 1 },
	} {
		t.Run(name, func(t *testing.T) {
			changed := plan.Freshness()
			mutate(&changed)
			if candidate.FreshAgainst(changed) {
				t.Fatal("candidate accepted changed complete evidence")
			}
		})
	}
	if _, err := json.Marshal(candidate); err == nil {
		t.Fatal("internal candidate crossed JSON boundary")
	}
	var decoded SambaIsolatedCandidate
	if json.Unmarshal([]byte(`{}`), &decoded) == nil {
		t.Fatal("JSON supplied candidate authority")
	}
}

func TestIsolatedSambaCandidateRefusesAbsentOrUnsupportedPlanWithoutPartialOutput(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	config.Shares.Shares[0].RelativePath = "."
	ordinary, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	config.Shares.Shares = []shareconfig.Share{}
	nfsOnly, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range []Plan{{}, ordinary, nfsOnly} {
		candidate, err := plan.SambaIsolatedCandidate()
		if !errors.Is(err, ErrNotReady) || candidate.FreshAgainst(plan.Freshness()) {
			t.Fatal("refused plan produced a usable isolated candidate")
		}
		p, g, n, s, roots, err := candidate.Documents()
		if !errors.Is(err, ErrNotReady) || p != "" || g != "" || n != "" || s != "" || roots != nil {
			t.Fatal("refused candidate leaked partial documents")
		}
	}
}
