// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package fileserviceplan

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
)

func TestNFSv3CandidateBindsSamePlanPolicyAndStorage(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	enabled, table, roots, err := candidate.Documents()
	_, originalTable := plan.RenderedCandidates()
	if err != nil || !enabled || table != originalTable || len(roots) != 1 {
		t.Fatal("NFS candidate lost its complete source policy", err)
	}
	root := roots[0]
	if root.ID != testExportID || root.RelativePath != "books" || root.ReadOnly ||
		root.Volume.VolumeID != "bulk" || root.Volume.FilesystemUUID != testVolumeUUID ||
		root.Volume.MountID != 73 || root.Volume.DeviceMajor != 9 || root.Volume.DeviceMinor != 1 ||
		len(root.Clients) != 1 || root.Clients[0] != config.NFS.Exports[0].Clients[0] ||
		!candidate.FreshAgainst(plan.Freshness()) {
		t.Fatal("NFS request is not bound to the same complete Plan")
	}
}

func TestNFSv3CandidateDoesNotAliasCallerOrReturnedRequests(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	config.NFS.Exports[0].RelativePath = "changed"
	config.NFS.Exports[0].Clients[0].Access = "ro"
	storage.Volumes[0].MountID++
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	_, table, roots, err := candidate.Documents()
	if err != nil || roots[0].RelativePath != "books" || roots[0].ReadOnly || roots[0].Volume.MountID != 73 {
		t.Fatal("Build retained caller-owned NFS inputs", err)
	}
	roots[0].ID = "changed"
	roots[0].Volume.MountID++
	roots[0].RelativePath = "changed"
	roots[0].Clients[0].Network = "192.0.2.1/32"
	roots[0].Clients[0].Access = "ro"
	_, after, unchanged, err := candidate.Documents()
	if err != nil || after != table || unchanged[0].ID != testExportID || unchanged[0].Volume.MountID != 73 ||
		unchanged[0].RelativePath != "books" || unchanged[0].Clients[0].Network != "127.0.0.1/32" || unchanged[0].Clients[0].Access != "rw" {
		t.Fatal("Documents exposed mutable candidate data", err)
	}
}

func TestNFSv3CandidateEmptyPolicyIsDisabledNotMissingOrUnsupported(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	config.NFS.Exports = []nfsconfig.Export{}
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	enabled, table, roots, err := candidate.Documents()
	if err != nil || enabled || table != "" || len(roots) != 0 || !candidate.FreshAgainst(plan.Freshness()) {
		t.Fatal("empty configured policy is not a bound disabled candidate", err)
	}
	if candidate, err := (Plan{}).NFSv3TCPCandidate(); !errors.Is(err, ErrNotReady) || !reflect.DeepEqual(candidate, NFSv3Candidate{}) {
		t.Fatal("zero Plan became a disabled configured service", err)
	}
	if enabled, table, roots, err := (NFSv3Candidate{}).Documents(); !errors.Is(err, ErrNotReady) || enabled || table != "" || roots != nil {
		t.Fatal("zero candidate returned partial or disabled documents", err)
	}
}

func TestNFSv3CandidateNeverDowngradesKerberosToSys(t *testing.T) {
	for _, security := range []string{"krb5", "krb5i", "krb5p"} {
		t.Run(security, func(t *testing.T) {
			config, active, identity, storage := planInputs(t)
			identity.KerberosReady = true
			other := config.NFS.Exports[0].Clients[0]
			other.Network, other.Security = "192.0.2.1/32", security
			config.NFS.Exports[0].Clients = append(config.NFS.Exports[0].Clients, other)
			plan, err := Build(config, active, identity, storage)
			if err != nil {
				t.Fatal("general desired preview refused its existing Kerberos contract", err)
			}
			_, before := plan.RenderedCandidates()
			candidate, err := plan.NFSv3TCPCandidate()
			if !errors.Is(err, ErrNotReady) || !reflect.DeepEqual(candidate, NFSv3Candidate{}) {
				t.Fatal("partial/mixed unsupported security was admitted", err)
			}
			_, after := plan.RenderedCandidates()
			if after != before || !strings.Contains(after, "sec="+security) {
				t.Fatal("refusal changed or downgraded the existing preview")
			}
		})
	}
}

func TestNFSv3CandidatePreservesPerExportAndPerClientAccess(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	config.NFS.Exports[0].RelativePath = "mixed"
	config.NFS.Exports[0].Clients[0].Access = "ro"
	writer := config.NFS.Exports[0].Clients[0]
	writer.Network, writer.Access = "192.0.2.1/32", "rw"
	config.NFS.Exports[0].Clients = append(config.NFS.Exports[0].Clients, writer)
	config.NFS.Exports = append(config.NFS.Exports, nfsconfig.Export{ID: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
		VolumeID: "bulk", RelativePath: "read-only", Clients: []nfsconfig.Client{config.NFS.Exports[0].Clients[0]}})
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	_, table, roots, err := candidate.Documents()
	if err != nil || len(roots) != 2 || roots[0].ReadOnly || !roots[1].ReadOnly ||
		roots[0].Clients[0].Access != "ro" || roots[0].Clients[1].Access != "rw" || roots[1].Clients[0].Access != "ro" {
		t.Fatal("a writer broadened another client/export", err)
	}
	config.NFS.Exports[0], config.NFS.Exports[1] = config.NFS.Exports[1], config.NFS.Exports[0]
	config.NFS.Exports[1].Clients[0], config.NFS.Exports[1].Clients[1] = config.NFS.Exports[1].Clients[1], config.NFS.Exports[1].Clients[0]
	reordered, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	other, err := reordered.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	_, otherTable, otherRoots, err := other.Documents()
	if err != nil || table != otherTable || !reflect.DeepEqual(roots, otherRoots) {
		t.Fatal("enumeration order changed NFS candidate", err)
	}
}

func TestNFSv3CandidateBindsEveryFreshnessFieldAndRefusesJSON(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*Freshness){
		func(f *Freshness) { f.PolicyRevision++ }, func(f *Freshness) { f.ActiveRevision++ },
		func(f *Freshness) { f.IdentityGeneration++ }, func(f *Freshness) { f.IdentityFingerprint[0]++ },
		func(f *Freshness) { f.StorageGeneration++ }, func(f *Freshness) { f.StorageFingerprint[0]++ },
	} {
		fresh := plan.Freshness()
		change(&fresh)
		if candidate.FreshAgainst(fresh) {
			t.Fatal("changed freshness accepted")
		}
	}
	if data, err := json.Marshal(candidate); err == nil || len(data) != 0 {
		t.Fatal("candidate serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &candidate); err == nil {
		t.Fatal("candidate deserialized")
	}
	if !candidate.FreshAgainst(plan.Freshness()) || (NFSv3Candidate{}).FreshAgainst(plan.Freshness()) {
		t.Fatal("JSON refusal changed the original or revived a zero candidate")
	}
}
