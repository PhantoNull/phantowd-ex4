// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func TestSambaShareCandidateBindsDeclaredRootAndPreservesWriter(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	sections, roots, err := plan.SambaShareCandidates()
	if err != nil || !reflect.DeepEqual(roots, []SambaShareRoot{{
		ID: "books", VolumeID: "bulk", RelativePath: "books", ReadOnly: false,
	}}) || !strings.Contains(sections, "path = /shares/books\n") ||
		!strings.Contains(sections, "write list = alice\n") || strings.Contains(sections, shareconfig.VolumeMountRoot) {
		t.Fatalf("share candidate lost its exact root/grant binding: %v", err)
	}
	// Neither mutable desired input nor the caller's result may replace the
	// original root, writer or fixed isolated destination of this Plan.
	config.Shares.Shares[0].RelativePath = "replacement"
	config.Shares.Shares[0].Grants[0].Access = "ro"
	roots[0].RelativePath, roots[0].ReadOnly = "replacement", true
	second, secondRoots, err := plan.SambaShareCandidates()
	if err != nil || sections != second || secondRoots[0].RelativePath != "books" || secondRoots[0].ReadOnly {
		t.Fatal("share candidate aliases caller-owned policy or result")
	}
	if plan.Freshness().StorageFingerprint == ([32]byte{}) || plan.Freshness().IdentityFingerprint == ([32]byte{}) {
		t.Fatal("candidate is detached from complete source/identity evidence")
	}
}

func TestSambaShareCandidateReadOnlyRootsAndUnsupportedCases(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	config.Shares.Shares[0].Grants[0].Access = "ro"
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	sections, roots, err := plan.SambaShareCandidates()
	if err != nil || len(roots) != 1 || !roots[0].ReadOnly ||
		!strings.Contains(sections, "read list = alice\n") || !strings.Contains(sections, "write list = \n") {
		t.Fatal("read-only share needs a read-only clone and no writer")
	}
	config.Shares.Shares[0].RelativePath = "."
	ordinary, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal("ordinary candidate must remain available:", err)
	}
	for _, candidate := range []Plan{{}, ordinary} {
		sections, roots, err := candidate.SambaShareCandidates()
		if !errors.Is(err, ErrNotReady) || sections != "" || roots != nil {
			t.Fatal("unsupported candidate leaked partial sections or root requests")
		}
	}
	config.Shares.Shares = []shareconfig.Share{}
	plan, err = Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	sections, roots, err = plan.SambaShareCandidates()
	if err != nil || roots == nil || len(roots) != 0 || strings.Contains(sections, "path =") {
		t.Fatal("NFS-only candidate invented an SMB root")
	}
}

func TestSambaShareCandidateSortsDisjointRootsWithoutBroadeningReadOnlyShare(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	config.Shares.Shares = append(config.Shares.Shares, shareconfig.Share{
		ID: "audio", Name: "Audio", VolumeID: "bulk", RelativePath: "media/audio",
		Grants: []shareconfig.Grant{{UserID: "writer", Access: "ro"}},
	})
	first, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	sections, roots, err := first.SambaShareCandidates()
	if err != nil || !reflect.DeepEqual(roots, []SambaShareRoot{
		{ID: "audio", VolumeID: "bulk", RelativePath: "media/audio", ReadOnly: true},
		{ID: "books", VolumeID: "bulk", RelativePath: "books", ReadOnly: false},
	}) {
		t.Fatal("roster-wide writer widened the separate read-only share")
	}
	config.Shares.Shares[0], config.Shares.Shares[1] = config.Shares.Shares[1], config.Shares.Shares[0]
	second, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	secondSections, secondRoots, err := second.SambaShareCandidates()
	if err != nil || sections != secondSections || !reflect.DeepEqual(roots, secondRoots) ||
		!first.FreshAgainst(second.Freshness()) {
		t.Fatal("equivalent source order changed candidate sections, roots or freshness")
	}
}
