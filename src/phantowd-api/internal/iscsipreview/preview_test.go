// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package iscsipreview

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func fixture() naspolicy.Config {
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: 1,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
				Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}},
				Users:   []shareconfig.User{}, Shares: []shareconfig.Share{}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}}},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
			Backings: []iscsipolicy.Backing{{ID: "backing", VolumeID: "bulk", RelativePath: "luns/not-opened.img", CapacityBytes: 4096, BlockSize: 512, Allocation: "sparse"}},
			Targets: []iscsipolicy.Target{{ID: "target", Name: "iqn.2001-04.com.example:target", State: "enabled",
				LUNs: []iscsipolicy.LUN{{ID: "lun", Number: 0, BackingID: "backing", Access: "rw"}},
				Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:peer",
					Authentication: iscsipolicy.Authentication{Mode: "mutual-chap", InitiatorUser: "private-in-user", InitiatorSecretRef: "private-in-ref", TargetUser: "private-out-user", TargetSecretRef: "private-out-ref"},
					Grants:         []iscsipolicy.Grant{{LUNID: "lun", Access: "ro"}}}}}}}}
}

func TestPreviewPreservesDesiredAccessWithoutCredentialsOrAuthority(t *testing.T) {
	config := fixture()
	before, _ := json.Marshal(config)
	p, err := Build(config)
	if err != nil || p.Format != Format || p.SchemaVersion != SchemaVersion || p.Scope != "desired-policy-only" || p.Revision != "1" ||
		p.StorageValidated || p.CredentialsValidated || p.RuntimeValidated || p.ActivationAvailable ||
		len(p.Targets) != 1 || len(p.Backings) != 1 || len(p.Limitations) == 0 {
		t.Fatalf("invalid desired preview: %+v err=%v", p, err)
	}
	if p.Targets[0].DesiredState != "enabled" || p.Targets[0].LUNs[0].Number != 0 || p.Targets[0].LUNs[0].Access != "rw" ||
		p.Targets[0].Initiators[0].DesiredAuthentication != "mutual-chap" || p.Targets[0].Initiators[0].Grants[0].Access != "ro" ||
		p.Backings[0].CapacityBytes != "4096" || p.Backings[0].VolumeID != "bulk" {
		t.Fatal("desired relationships were normalized or lost")
	}
	encoded, err := json.Marshal(p)
	if err != nil || len(encoded) > MaxOutputBytes {
		t.Fatal("invalid encoded output")
	}
	for _, private := range []string{"private-in-user", "private-out-user", "private-in-ref", "private-out-ref", "secret_ref", string(config.FileServices.Shares.Volumes[0].FilesystemUUID)} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("preview leaked private field %s", private)
		}
	}
	after, _ := json.Marshal(config)
	if string(before) != string(after) {
		t.Fatal("preview changed input")
	}
	// Returned rows, grants and limitations must not alias the source or each
	// other: future rendering/editing cannot rewrite the coherent policy.
	p.Backings[0].ID = "changed"
	p.Targets[0].LUNs[0].Access = "ro"
	p.Targets[0].Initiators[0].Grants[0].Access = "rw"
	p.Limitations[0] = "changed"
	again, err := Build(config)
	if err != nil || again.Backings[0].ID != "backing" || again.Targets[0].LUNs[0].Access != "rw" ||
		again.Targets[0].Initiators[0].Grants[0].Access != "ro" || again.Limitations[0] == "changed" {
		t.Fatal("returned display rows share mutable state")
	}
}

func TestPreviewRetainsExact64BitDecimalValues(t *testing.T) {
	config := fixture()
	config.Revision = math.MaxUint64
	config.FileServices.Revision = config.Revision
	config.FileServices.Shares.Revision = config.Revision
	config.FileServices.NFS.Revision, config.FileServices.NFS.VolumeRevision = config.Revision, config.Revision
	config.ISCSI.Revision, config.ISCSI.VolumeRevision = config.Revision, config.Revision
	config.ISCSI.Backings[0].CapacityBytes = math.MaxInt64 / 4096 * 4096
	p, err := Build(config)
	if err != nil || p.Revision != "18446744073709551615" || p.Backings[0].CapacityBytes != "9223372036854771712" {
		t.Fatalf("64-bit desired values lost precision: %+v err=%v", p, err)
	}
	encoded, _ := json.Marshal(p)
	if !strings.Contains(string(encoded), `"revision":"18446744073709551615"`) || !strings.Contains(string(encoded), `"capacity_bytes":"9223372036854771712"`) {
		t.Fatal("large integer was emitted as a JSON number")
	}
}

func TestInvalidWholePolicyReturnsNoPartialPreview(t *testing.T) {
	for _, mutate := range []func(*naspolicy.Config){
		func(c *naspolicy.Config) { c.Revision++ },
		func(c *naspolicy.Config) { c.FileServices.Revision++ },
		func(c *naspolicy.Config) { c.FileServices.Shares.Revision++ },
		func(c *naspolicy.Config) { c.FileServices.NFS.Revision++ },
		func(c *naspolicy.Config) { c.FileServices.NFS.VolumeRevision++ },
		func(c *naspolicy.Config) { c.ISCSI.Revision++ },
		func(c *naspolicy.Config) { c.ISCSI.VolumeRevision++ },
		func(c *naspolicy.Config) { c.ISCSI.Backings[0].VolumeID = "foreign" },
		func(c *naspolicy.Config) { c.ISCSI.Targets[0].Initiators[0].Grants[0].LUNID = "foreign" },
		func(c *naspolicy.Config) { c.ISCSI.Targets[0].Initiators[0].Authentication.Mode = "none" },
		func(c *naspolicy.Config) {
			c.ISCSI.Targets[0].LUNs[0].Access = "ro"
			c.ISCSI.Targets[0].Initiators[0].Grants[0].Access = "rw"
		},
		func(c *naspolicy.Config) { c.ISCSI.Backings[0].RelativePath = "../PRIVATE" },
		func(c *naspolicy.Config) { c.ISCSI.Backings[0].CapacityBytes++ },
	} {
		config := fixture()
		mutate(&config)
		p, err := Build(config)
		if err != ErrInvalid || err.Error() != "invalid desired iSCSI preview" || !reflect.DeepEqual(p, Preview{}) {
			t.Fatal("invalid configuration yielded partial or nonredacted preview")
		}
	}
	if p, err := Build(naspolicy.Config{}); err != ErrInvalid || !reflect.DeepEqual(p, Preview{}) {
		t.Fatal("zero configuration was treated as empty policy")
	}
}

func TestExplicitEmptyPolicyRemainsExplicit(t *testing.T) {
	config := fixture()
	config.ISCSI.Backings, config.ISCSI.Targets = []iscsipolicy.Backing{}, []iscsipolicy.Target{}
	p, err := Build(config)
	if err != nil || p.Targets == nil || p.Backings == nil || len(p.Targets) != 0 || len(p.Backings) != 0 || p.Revision != "1" {
		t.Fatal("explicit empty policy became missing evidence")
	}
}

func TestDenseDesiredPolicyIsCompleteAndBounded(t *testing.T) {
	config := fixture()
	config.ISCSI.Backings, config.ISCSI.Targets = []iscsipolicy.Backing{}, []iscsipolicy.Target{}
	for ti := 0; ti < 4; ti++ {
		target := iscsipolicy.Target{ID: iscsipolicy.TargetID(fmt.Sprintf("t-%d", ti)),
			Name: fmt.Sprintf("iqn.2001-04.com.example:t%d", ti), State: "disabled"}
		for li := 0; li < iscsipolicy.MaxLUNs; li++ {
			backing := iscsipolicy.Backing{ID: iscsipolicy.BackingID(fmt.Sprintf("b-%d-%d", ti, li)), VolumeID: "bulk",
				RelativePath: fmt.Sprintf("luns/t%d/d%d.img", ti, li), CapacityBytes: 4096, BlockSize: 512, Allocation: "preallocated"}
			config.ISCSI.Backings = append(config.ISCSI.Backings, backing)
			target.LUNs = append(target.LUNs, iscsipolicy.LUN{ID: iscsipolicy.LUNID(fmt.Sprintf("l-%d-%d", ti, li)), Number: uint16(li), BackingID: backing.ID, Access: "rw"})
		}
		for pi := 0; pi < 16; pi++ {
			peer := iscsipolicy.Initiator{Name: fmt.Sprintf("iqn.2001-04.com.example:p%d-%d", ti, pi),
				Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: fmt.Sprintf("u%d-%d", ti, pi), InitiatorSecretRef: iscsipolicy.SecretRef(fmt.Sprintf("r-%d-%d", ti, pi))}}
			for _, lun := range target.LUNs {
				access := "ro"
				if pi%2 == 1 {
					access = "rw"
				}
				peer.Grants = append(peer.Grants, iscsipolicy.Grant{LUNID: lun.ID, Access: access})
			}
			target.Initiators = append(target.Initiators, peer)
		}
		config.ISCSI.Targets = append(config.ISCSI.Targets, target)
	}
	preview, err := Build(config)
	if err != nil || len(preview.Backings) != iscsipolicy.MaxBackings || len(preview.Targets) != 4 {
		t.Fatalf("dense supported policy lost rows: err=%v", err)
	}
	grants := 0
	for ti, target := range preview.Targets {
		if len(target.LUNs) != 16 || len(target.Initiators) != 16 {
			t.Fatal("dense target was truncated")
		}
		for pi, peer := range target.Initiators {
			if len(peer.Grants) != 16 {
				t.Fatal("dense permission roster was truncated")
			}
			for gi, grant := range peer.Grants {
				original := config.ISCSI.Targets[ti].Initiators[pi].Grants[gi]
				if grant.LUNID != string(original.LUNID) || grant.Access != original.Access {
					t.Fatal("dense desired grant changed")
				}
			}
			grants += len(peer.Grants)
		}
	}
	encoded, err := json.Marshal(preview)
	if err != nil || grants != 1024 || len(encoded) > MaxOutputBytes {
		t.Fatal("dense preview exceeded bounds or lost grants")
	}
	t.Logf("64 backings, 4 targets, 64 initiators, 1024 grants: %d encoded bytes", len(encoded))
}

func FuzzPreviewNeverGrantsAuthorityOrReturnsPartialFailure(f *testing.F) {
	valid, _ := json.Marshal(fixture())
	f.Add(valid)
	f.Add([]byte(`{}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		config, err := naspolicy.Decode(bytes.NewReader(input))
		if err != nil {
			return
		}
		preview, err := Build(config)
		if err != nil {
			if err != ErrInvalid || !reflect.DeepEqual(preview, Preview{}) {
				t.Fatal("failed preview retained partial data or private error")
			}
			return
		}
		encoded, err := json.Marshal(preview)
		if err != nil || len(encoded) > MaxOutputBytes || preview.StorageValidated || preview.CredentialsValidated ||
			preview.RuntimeValidated || preview.ActivationAvailable || len(preview.Targets) != len(config.ISCSI.Targets) ||
			len(preview.Backings) != len(config.ISCSI.Backings) {
			t.Fatal("desired input acquired runtime authority or lost bounded completeness")
		}
	})
}
