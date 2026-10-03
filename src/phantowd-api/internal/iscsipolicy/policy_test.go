// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package iscsipolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"math/rand/v2"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func volumes() shareconfig.Config {
	return shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 7,
		Volumes: []shareconfig.Volume{{ID: "volume-a", FilesystemUUID: "12345678-1234-1234-1234-123456789abc"},
			{ID: "volume-b", FilesystemUUID: "23456789-1234-1234-1234-123456789abc"}},
		Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
}

func validPolicy() Policy {
	return Policy{Format: Format, SchemaVersion: 1, Revision: 2, VolumeRevision: 7,
		Backings: []Backing{
			{ID: "backing-a", VolumeID: "volume-a", RelativePath: "luns/data.img", CapacityBytes: 1 << 30, BlockSize: 512, Allocation: "preallocated"},
			{ID: "backing-b", VolumeID: "volume-b", RelativePath: "luns/data.img", CapacityBytes: 2 << 30, BlockSize: 4096, Allocation: "sparse"}},
		Targets: []Target{{ID: "target-a", Name: "iqn.2001-04.com.example:storage", State: "disabled",
			LUNs: []LUN{{ID: "lun-a", Number: 0, BackingID: "backing-a", Access: "rw"}, {ID: "lun-b", Number: 65535, BackingID: "backing-b", Access: "ro"}},
			Initiators: []Initiator{
				{Name: "iqn.2001-04.com.example:client-a", Authentication: Authentication{Mode: "chap", InitiatorUser: "Client_a@example", InitiatorSecretRef: "secret-a"},
					Grants: []Grant{{LUNID: "lun-a", Access: "rw"}, {LUNID: "lun-b", Access: "ro"}}},
				{Name: "iqn.2001-04.com.example:client-b", Authentication: Authentication{Mode: "mutual-chap", InitiatorUser: "client-b", InitiatorSecretRef: "secret-b", TargetUser: "target", TargetSecretRef: "secret-target-b"},
					Grants: []Grant{{LUNID: "lun-a", Access: "ro"}}}}}}}
}

func encoded(t *testing.T, p Policy) string {
	t.Helper()
	b, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPolicyRoundTripAndNonMutation(t *testing.T) {
	p, v := validPolicy(), volumes()
	beforeP, beforeV := encoded(t, p), mustJSON(t, v)
	if err := p.Validate(v); err != nil {
		t.Fatal(err)
	}
	got, err := Decode(strings.NewReader(beforeP), v)
	if err != nil || !reflect.DeepEqual(p, got) {
		t.Fatalf("round trip: %v", err)
	}
	if encoded(t, p) != beforeP || mustJSON(t, v) != beforeV {
		t.Fatal("input mutated")
	}
	p.Backings, p.Targets = []Backing{}, []Target{}
	if _, err := Decode(strings.NewReader(encoded(t, p)), v); err != nil {
		t.Fatal(err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	b, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestPolicyRefusals(t *testing.T) {
	cases := map[string]func(*Policy){
		"format":            func(p *Policy) { p.Format = "other" },
		"schema":            func(p *Policy) { p.SchemaVersion = 2 },
		"revision":          func(p *Policy) { p.Revision = 0 },
		"stale":             func(p *Policy) { p.VolumeRevision-- },
		"missing backings":  func(p *Policy) { p.Backings = nil },
		"missing targets":   func(p *Policy) { p.Targets = nil },
		"backing id":        func(p *Policy) { p.Backings[0].ID = "../escape" },
		"duplicate backing": func(p *Policy) { p.Backings[1].ID = p.Backings[0].ID },
		"unknown volume":    func(p *Policy) { p.Backings[0].VolumeID = "missing" },
		"zero capacity":     func(p *Policy) { p.Backings[0].CapacityBytes = 0 },
		"too small":         func(p *Policy) { p.Backings[0].CapacityBytes = 511 },
		"alignment":         func(p *Policy) { p.Backings[0].CapacityBytes++ },
		"overflow":          func(p *Policy) { p.Backings[0].CapacityBytes = uint64(math.MaxInt64) + 1 },
		"block size":        func(p *Policy) { p.Backings[0].BlockSize = 0 },
		"allocation":        func(p *Policy) { p.Backings[0].Allocation = "" },
		"orphan backing": func(p *Policy) {
			p.Backings = append(p.Backings, Backing{ID: "orphan", VolumeID: "volume-a", RelativePath: "orphan.img", CapacityBytes: 512, BlockSize: 512, Allocation: "sparse"})
		},
		"duplicate target": func(p *Policy) { p.Targets = append(p.Targets, p.Targets[0]) },
		"target id":        func(p *Policy) { p.Targets[0].ID = "" },
		"target state":     func(p *Policy) { p.Targets[0].State = "" },
		"target name":      func(p *Policy) { p.Targets[0].Name = "IQN.2001-04.com.example:target" },
		"no luns":          func(p *Policy) { p.Targets[0].LUNs = nil },
		"no initiators":    func(p *Policy) { p.Targets[0].Initiators = nil },
		"lun id":           func(p *Policy) { p.Targets[0].LUNs[0].ID = "" },
		"duplicate lun id": func(p *Policy) { p.Targets[0].LUNs[1].ID = p.Targets[0].LUNs[0].ID },
		"duplicate number": func(p *Policy) { p.Targets[0].LUNs[1].Number = 0 },
		"unknown backing":  func(p *Policy) { p.Targets[0].LUNs[0].BackingID = "missing" },
		"shared backing":   func(p *Policy) { p.Targets[0].LUNs[1].BackingID = p.Targets[0].LUNs[0].BackingID },
		"lun access":       func(p *Policy) { p.Targets[0].LUNs[0].Access = "" },
		"wildcard":         func(p *Policy) { p.Targets[0].Initiators[0].Name = "*" },
		"duplicate peer":   func(p *Policy) { p.Targets[0].Initiators[1].Name = p.Targets[0].Initiators[0].Name },
		"no grants":        func(p *Policy) { p.Targets[0].Initiators[0].Grants = nil },
		"foreign lun":      func(p *Policy) { p.Targets[0].Initiators[0].Grants[0].LUNID = "foreign" },
		"duplicate grant": func(p *Policy) {
			p.Targets[0].Initiators[0].Grants = append(p.Targets[0].Initiators[0].Grants, p.Targets[0].Initiators[0].Grants[0])
		},
		"grant access":        func(p *Policy) { p.Targets[0].Initiators[0].Grants[0].Access = "" },
		"readonly escalation": func(p *Policy) { p.Targets[0].Initiators[0].Grants[1].Access = "rw" },
		"no auth":             func(p *Policy) { p.Targets[0].Initiators[0].Authentication.Mode = "none" },
		"missing user":        func(p *Policy) { p.Targets[0].Initiators[0].Authentication.InitiatorUser = "" },
		"bad user":            func(p *Policy) { p.Targets[0].Initiators[0].Authentication.InitiatorUser = "user\nadmin" },
		"missing secret":      func(p *Policy) { p.Targets[0].Initiators[0].Authentication.InitiatorSecretRef = "" },
		"path secret":         func(p *Policy) { p.Targets[0].Initiators[0].Authentication.InitiatorSecretRef = "/etc/secret" },
		"chap extra user":     func(p *Policy) { p.Targets[0].Initiators[0].Authentication.TargetUser = "target" },
		"chap extra ref":      func(p *Policy) { p.Targets[0].Initiators[0].Authentication.TargetSecretRef = "extra" },
		"mutual missing user": func(p *Policy) { p.Targets[0].Initiators[1].Authentication.TargetUser = "" },
		"mutual missing ref":  func(p *Policy) { p.Targets[0].Initiators[1].Authentication.TargetSecretRef = "" },
		"mutual reflection": func(p *Policy) {
			a := &p.Targets[0].Initiators[1].Authentication
			a.TargetSecretRef = a.InitiatorSecretRef
		},
		"shared inbound":           func(p *Policy) { p.Targets[0].Initiators[1].Authentication.InitiatorSecretRef = "secret-a" },
		"opposite direction reuse": func(p *Policy) { p.Targets[0].Initiators[1].Authentication.TargetSecretRef = "secret-a" },
	}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			p := validPolicy()
			change(&p)
			if p.Validate(volumes()) != ErrInvalid {
				t.Fatal("direct value accepted")
			}
			assertRefused(t, encoded(t, p))
		})
	}
	v := volumes()
	v.Volumes[1].FilesystemUUID = v.Volumes[0].FilesystemUUID
	if validPolicy().Validate(v) != ErrInvalid {
		t.Fatal("invalid external policy accepted")
	}
}

func assertRefused(t *testing.T, input string) {
	t.Helper()
	p, err := Decode(strings.NewReader(input), volumes())
	if err != ErrInvalid || !reflect.DeepEqual(p, Policy{}) {
		t.Fatalf("not redacted all-or-error: %v", err)
	}
}

func TestBackingPathAndIQNProfiles(t *testing.T) {
	for _, name := range []string{"iqn.2001-04.com.example", "iqn.0001-01.com.example:disk", "iqn.9999-12.com.example:disk.1:lun-2", "iqn.2001-04.com.example:" + strings.Repeat("x", 199)} {
		if !iqn(name) {
			t.Fatalf("name refused (%d bytes)", len(name))
		}
	}
	for _, name := range []string{"iqn.0000-01.com.example", "iqn.2001-00.com.example", "iqn.2001-13.com.example", "iqn.2001-1.com.example", "iqn.2001-04.example", "iqn.2001-04.com..example", "iqn.2001-04.com.-example", "iqn.2001-04.com.example-", "iqn.2001-04.com.example.", "iqn.2001-04.com.example:", "iqn.2001-04.com.example:UPPER", "iqn.2001-04.com.example:é", "iqn.2001-04.com.example:../x", "iqn.2001-04.com.example:" + strings.Repeat("x", 202), "eui.02004567a425678d", "naa.52004567ba64678d"} {
		if iqn(name) {
			t.Fatal("invalid/unsupported name accepted")
		}
	}
	for _, path := range []string{"data.img", "folder/é.img", "a/b"} {
		if !filePath(path) {
			t.Fatal("safe relative file path refused")
		}
	}
	for _, path := range []string{"", ".", "/data", "../data", "a/../b", "a//b", "a/./b", "a\\b", "C:file", "a\x00b", "a\x7fb", strings.Repeat("x", 1025), string([]byte{0xff})} {
		if filePath(path) {
			t.Fatal("unsafe path accepted")
		}
	}
	for _, path := range []string{"luns/data.img", "luns", "luns/data.img/child"} {
		p := validPolicy()
		p.Backings[1].VolumeID = "volume-a"
		p.Backings[1].RelativePath = path
		if p.Validate(volumes()) != ErrInvalid {
			t.Fatal("backing alias accepted")
		}
	}
	p := validPolicy()
	p.Backings[1].VolumeID = "volume-a"
	p.Backings[1].RelativePath = "luns/data.img2"
	if p.Validate(volumes()) != nil {
		t.Fatal("component boundary incorrectly overlaps")
	}
}

func twoTargets() Policy {
	p := validPolicy()
	b := p.Targets[0].LUNs[1]
	p.Targets[0].LUNs = p.Targets[0].LUNs[:1]
	p.Targets[0].Initiators[0].Grants = p.Targets[0].Initiators[0].Grants[:1]
	p.Targets = append(p.Targets, Target{ID: "target-b", Name: "iqn.2001-04.com.example:storage-b", State: "enabled",
		LUNs: []LUN{b}, Initiators: []Initiator{{Name: "iqn.2001-04.com.example:client-a",
			Authentication: Authentication{Mode: "chap", InitiatorUser: "Client_a@example", InitiatorSecretRef: "secret-other-target"},
			Grants:         []Grant{{LUNID: b.ID, Access: "ro"}}}}})
	return p
}

func TestCrossTargetBoundaries(t *testing.T) {
	p := twoTargets()
	// The same initiator may be authorized to two different targets with
	// independently assigned credentials; LUN numbers are target-local.
	p.Targets[1].LUNs[0].Number = 0
	if p.Validate(volumes()) != nil {
		t.Fatal("independent target refused")
	}
	for _, change := range []func(*Policy){
		func(p *Policy) { p.Targets[1].Name = p.Targets[0].Name },
		func(p *Policy) { p.Targets[1].LUNs[0].ID = p.Targets[0].LUNs[0].ID },
		func(p *Policy) { p.Targets[1].LUNs[0].BackingID = p.Targets[0].LUNs[0].BackingID },
		func(p *Policy) { p.Targets[1].Initiators[0].Grants[0].LUNID = p.Targets[0].LUNs[0].ID },
		func(p *Policy) { p.Targets[1].Initiators[0].Authentication.InitiatorSecretRef = "secret-target-b" },
	} {
		p := twoTargets()
		change(&p)
		if p.Validate(volumes()) != ErrInvalid {
			t.Fatal("cross-target conflict accepted")
		}
		assertRefused(t, encoded(t, p))
	}
}

func TestStrictJSONRequiredFields(t *testing.T) {
	input := encoded(t, validPolicy())
	for _, bad := range []string{
		strings.Replace(input, `"number":0,`, "", 1),
		strings.Replace(input, `"number":0`, `"number":null`, 1),
		strings.Replace(input, `"number":0`, `"number":false`, 1),
		strings.Replace(input, `"number":0`, `"number":"0"`, 1),
		strings.Replace(input, `"number":0`, `"number":0.0`, 1),
		strings.Replace(input, `"number":0`, `"number":65536`, 1),
		strings.Replace(input, `"number":0`, `"number":-1`, 1),
		strings.Replace(input, `"number":0`, `"number":0,"number":0`, 1),
		strings.Replace(input, `"number":0`, `"Number":0`, 1),
		strings.Replace(input, `"number":0`, `"number":0,"state":"enabled"`, 1),
		strings.Replace(input, `"relative_path":"luns/data.img"`, `"relative_path":"\ud800"`, 1),
		strings.Replace(input, `"authentication":{`, `"authentication":{"password":"secret",`, 1),
		input + `{}`, `[]`, `null`, string([]byte{0xff}),
	} {
		assertRefused(t, bad)
	}
	var root map[string]any
	if err := json.Unmarshal([]byte(input), &root); err != nil {
		t.Fatal(err)
	}
	paths := [][]string{{}, {"backings", "0"}, {"targets", "0"}, {"targets", "0", "luns", "0"}, {"targets", "0", "initiators", "0"}, {"targets", "0", "initiators", "0", "authentication"}, {"targets", "0", "initiators", "0", "grants", "0"}}
	for _, path := range paths {
		original := at(root, path)
		for key := range original {
			// The absent outbound pair is allowed only in one-way CHAP.
			var copy map[string]any
			_ = json.Unmarshal([]byte(input), &copy)
			delete(at(copy, path), key)
			t.Run(strings.Join(path, "/")+"/"+key, func(t *testing.T) { assertRefused(t, mustJSON(t, copy)) })
		}
	}
}

func at(root map[string]any, path []string) map[string]any {
	var value any = root
	for _, key := range path {
		if key == "0" {
			value = value.([]any)[0]
		} else {
			value = value.(map[string]any)[key]
		}
	}
	return value.(map[string]any)
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) { return 0, errors.New("private I/O detail") }

type countingSpaces struct{ count int }

func (r *countingSpaces) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = ' '
	}
	r.count += len(p)
	return len(p), nil
}

func TestReadBoundAndRedaction(t *testing.T) {
	for _, r := range []io.Reader{nil, errorReader{}} {
		p, err := Decode(r, volumes())
		if err != ErrInvalid || !reflect.DeepEqual(p, Policy{}) {
			t.Fatal("reader failure leaked result")
		}
	}
	r := &countingSpaces{}
	if _, err := Decode(r, volumes()); err != ErrInvalid || r.count != MaxInputBytes+1 {
		t.Fatal("read not bounded to limit plus one")
	}
	assertRefused(t, strings.Repeat(" ", MaxInputBytes+1))
}

func TestFixedMalformedInputProperties(t *testing.T) {
	base := []byte(encoded(t, validPolicy()))
	r := rand.New(rand.NewPCG(901, 2026))
	for i := range 2048 {
		candidate := bytes.Clone(base)
		for range 1 + r.IntN(8) {
			candidate[r.IntN(len(candidate))] = byte(r.IntN(256))
		}
		p, err := Decode(bytes.NewReader(candidate), volumes())
		if err != nil {
			if err != ErrInvalid || !reflect.DeepEqual(p, Policy{}) {
				t.Fatalf("partial at %d", i)
			}
			continue
		}
		if p.Validate(volumes()) != nil {
			t.Fatalf("invalid accepted at %d", i)
		}
		again, err := Decode(strings.NewReader(encoded(t, p)), volumes())
		if err != nil || !reflect.DeepEqual(p, again) {
			t.Fatalf("accepted value not stable at %d", i)
		}
	}
}

func TestCollectionAndFieldBounds(t *testing.T) {
	for _, mutate := range []func(*Policy){
		func(p *Policy) { p.Targets = make([]Target, MaxTargets+1) },
		func(p *Policy) { p.Backings = make([]Backing, MaxBackings+1) },
		func(p *Policy) { p.Targets[0].LUNs = make([]LUN, MaxLUNs+1) },
		func(p *Policy) { p.Targets[0].Initiators = make([]Initiator, MaxInitiators+1) },
		func(p *Policy) { p.Targets[0].Initiators[0].Grants = make([]Grant, MaxLUNs+1) },
		func(p *Policy) { p.Targets[0].ID = TargetID(strings.Repeat("x", 65)) },
		func(p *Policy) { p.Targets[0].Initiators[0].Authentication.InitiatorUser = strings.Repeat("x", 129) },
	} {
		p := validPolicy()
		mutate(&p)
		if p.Validate(volumes()) != ErrInvalid {
			t.Fatal("bound not enforced")
		}
	}
	// Structurally unique, bounded fields may still exceed the aggregate JSON cap.
	p := Policy{Format: Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 7, Backings: []Backing{}, Targets: []Target{}}
	for target := range 4 {
		x := Target{ID: TargetID(fmt.Sprintf("target-%d", target)), Name: fmt.Sprintf("iqn.2001-04.com.example:target-%d", target), State: "enabled", LUNs: []LUN{}, Initiators: []Initiator{}}
		for lun := range MaxLUNs {
			id := fmt.Sprintf("object-%d-%d", target, lun)
			p.Backings = append(p.Backings, Backing{ID: BackingID(id), VolumeID: "volume-a", RelativePath: id + strings.Repeat("x", 980), CapacityBytes: 4096, BlockSize: 4096, Allocation: "preallocated"})
			x.LUNs = append(x.LUNs, LUN{ID: LUNID(id), Number: uint16(lun), BackingID: BackingID(id), Access: "rw"})
		}
		for peer := range MaxInitiators {
			i := Initiator{Name: fmt.Sprintf("iqn.2001-04.com.example:peer-%d-%d", target, peer), Authentication: Authentication{Mode: "chap", InitiatorUser: "peer", InitiatorSecretRef: SecretRef(fmt.Sprintf("secret-%d-%d", target, peer))}, Grants: []Grant{}}
			for _, lun := range x.LUNs {
				i.Grants = append(i.Grants, Grant{LUNID: lun.ID, Access: "rw"})
			}
			x.Initiators = append(x.Initiators, i)
		}
		p.Targets = append(p.Targets, x)
	}
	if len(encoded(t, p)) <= MaxInputBytes {
		t.Fatal("aggregate bound fixture too small")
	}
	if p.Validate(volumes()) != ErrInvalid {
		t.Fatal("aggregate bound not enforced")
	}
}
