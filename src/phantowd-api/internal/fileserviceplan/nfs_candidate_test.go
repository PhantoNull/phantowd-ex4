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

func TestNFSv3CandidateEquivalenceRequiresValidCompleteCandidates(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	first, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	a, _ := first.NFSv3TCPCandidate()
	b, _ := second.NFSv3TCPCandidate()
	if !a.EquivalentTo(b) || !b.EquivalentTo(a) || !a.EquivalentTo(a) {
		t.Fatal("identical independently compiled candidate data refused")
	}
	if a.EquivalentTo(NFSv3Candidate{}) || (NFSv3Candidate{}).EquivalentTo(a) || (NFSv3Candidate{}).EquivalentTo(NFSv3Candidate{}) {
		t.Fatal("invalid candidate gained equivalence")
	}
}

func TestNFSv3CandidateEquivalenceRejectsSameTextWithChangedEvidence(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := plan.NFSv3TCPCandidate()
	_, table, _, _ := original.Documents()
	for _, change := range []func(*uint64, *IdentitySnapshot, *StorageSnapshot){
		func(a *uint64, _ *IdentitySnapshot, _ *StorageSnapshot) { *a++ },
		func(_ *uint64, i *IdentitySnapshot, _ *StorageSnapshot) { i.Generation++ },
		func(_ *uint64, i *IdentitySnapshot, _ *StorageSnapshot) { i.Fingerprint[0] ^= 1 },
		func(_ *uint64, _ *IdentitySnapshot, s *StorageSnapshot) { s.Generation++ },
		func(_ *uint64, _ *IdentitySnapshot, s *StorageSnapshot) { s.OwnerFingerprint[0] ^= 1 },
		func(_ *uint64, _ *IdentitySnapshot, s *StorageSnapshot) { s.Volumes[0].MountID++ },
	} {
		a, i, s := active, identity, storage
		s.Volumes = append([]ObservedVolume(nil), storage.Volumes...)
		change(&a, &i, &s)
		changed, err := Build(config, a, i, s)
		if err != nil {
			t.Fatal(err)
		}
		candidate, _ := changed.NFSv3TCPCandidate()
		_, otherTable, _, _ := candidate.Documents()
		if table != otherTable {
			t.Fatal("test did not retain identical rendered exports")
		}
		if original.EquivalentTo(candidate) || candidate.EquivalentTo(original) {
			t.Fatal("same rendered text hid changed evidence")
		}
	}
}

func TestNFSv3CandidateEquivalenceRejectsChangedDefinitionAtSameRevision(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	original, _ := plan.NFSv3TCPCandidate()
	for _, change := range []func(*nfsconfig.Export){
		func(e *nfsconfig.Export) { e.RelativePath = "other" },
		func(e *nfsconfig.Export) { e.Clients[0].Access = "ro" },
		func(e *nfsconfig.Export) { e.Clients[0].Network = "127.0.0.2/32" },
		func(e *nfsconfig.Export) { e.ID = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff" },
	} {
		changed := config
		changed.NFS.Exports = append([]nfsconfig.Export(nil), config.NFS.Exports...)
		changed.NFS.Exports[0].Clients = append([]nfsconfig.Client(nil), config.NFS.Exports[0].Clients...)
		change(&changed.NFS.Exports[0])
		otherPlan, err := Build(changed, active, identity, storage)
		if err != nil {
			t.Fatal(err)
		}
		other, _ := otherPlan.NFSv3TCPCandidate()
		_, originalText, _, _ := original.Documents()
		_, changedText, _, _ := other.Documents()
		if originalText == changedText {
			t.Fatal("test did not change the export definition")
		}
		if !other.FreshAgainst(plan.Freshness()) {
			t.Fatal("test changed freshness instead of definition")
		}
		if original.EquivalentTo(other) || other.EquivalentTo(original) {
			t.Fatal("changed definition at the same revision accepted")
		}
	}
}

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

func TestNFSv3CandidateMatchesCompleteOriginalStorageOnly(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	if !candidate.FreshAgainstStorage(storage) {
		t.Fatal("candidate lost its original complete storage tuple")
	}
}

func TestNFSv3CandidateStorageMatchRefusesEveryChangedBinding(t *testing.T) {
	config, active, identity, storage := planInputs(t)
	plan, err := Build(config, active, identity, storage)
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*StorageSnapshot){
		func(s *StorageSnapshot) { s.Complete = false },
		func(s *StorageSnapshot) { s.Generation++ },
		func(s *StorageSnapshot) { s.OwnerFingerprint[0] ^= 1 },
		func(s *StorageSnapshot) { s.Volumes = nil },
		func(s *StorageSnapshot) { s.Volumes[0].MountID++ },
		func(s *StorageSnapshot) { s.Volumes[0].DeviceMajor++ },
		func(s *StorageSnapshot) { s.Volumes[0].DeviceMinor++ },
		func(s *StorageSnapshot) { s.Volumes[0].FilesystemUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa" },
		func(s *StorageSnapshot) { s.Volumes[0].ReadOnly = !s.Volumes[0].ReadOnly },
		func(s *StorageSnapshot) { s.Volumes[0].MountPath += "-changed" },
		func(s *StorageSnapshot) { s.Volumes[0].Compatibility = CompatibilityUnqualified },
		func(s *StorageSnapshot) { s.Volumes = append(s.Volumes, s.Volumes[0]) },
	} {
		altered := storage
		altered.Volumes = append([]ObservedVolume(nil), storage.Volumes...)
		change(&altered)
		if candidate.FreshAgainstStorage(altered) {
			t.Fatal("changed storage still matched original candidate")
		}
	}
	if (NFSv3Candidate{}).FreshAgainstStorage(storage) {
		t.Fatal("zero candidate matched storage")
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
