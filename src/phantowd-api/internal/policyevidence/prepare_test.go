// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func nextPolicy(t testing.TB, revision uint64) naspolicy.Config {
	t.Helper()
	c, err := naspolicy.Decode(bytes.NewReader(policy(t, revision)))
	if err != nil {
		t.Fatal(err)
	}
	return c
}
func fixedEntropy(b []byte) (int, error) {
	for i := range b {
		b[i] = byte(i + 1)
	}
	return len(b), nil
}

func TestPreparationRetainsExactBaseAndStoreEncodedWholeCandidate(t *testing.T) {
	base := append(policy(t, 7), '\n')
	next := nextPolicy(t, 8)
	before, _ := json.Marshal(next)
	p, err := prepare(installation, base, next, fixedEntropy)
	if err != nil {
		t.Fatal(err)
	}
	gotBase, _ := p.BaseBytes()
	candidate, _ := p.CandidateBytes()
	i, _ := p.Intent()
	wire, err := EncodeIntent(i)
	if err != nil || !bytes.Equal(gotBase, base) || !bytes.Equal(candidate, before) || i.value.BaseSHA256 != digest(base) || i.value.NextSHA256 != digest(candidate) || i.value.BaseRevision != 7 || i.value.NextRevision != 8 || i.value.OperationID != "0102030405060708090a0b0c0d0e0f10" {
		t.Fatal("exact bytes/revisions or private generated binding lost")
	}
	for _, tc := range []struct {
		current []byte
		kind    Kind
	}{{base, IntentBaseObserved}, {candidate, PublicationUnconfirmed}} {
		d, err := Match(Evidence{InstallationID: installation, Intent: Slot{Present, wire}, Receipt: Slot{State: Absent}, Current: Slot{Present, tc.current}})
		if err != nil || d.Kind() != tc.kind {
			t.Fatal("preparation falsely confirmed or lost binding", d, err)
		}
	}
	// Caller inputs and every returned byte slice remain independently owned.
	base[0] = '!'
	next.ISCSI.Targets[0].Name = "changed"
	gotBase[0] = '!'
	candidate[0] = '!'
	wire[0] = '!'
	againBase, _ := p.BaseBytes()
	againCandidate, _ := p.CandidateBytes()
	againIntent, _ := p.Intent()
	againWire, _ := EncodeIntent(againIntent)
	if againBase[0] != '{' || againCandidate[0] != '{' || !bytes.Equal(againCandidate, before) || againWire[0] != '{' {
		t.Fatal("prepared operation aliases caller data")
	}
	copyPlan := p
	if b, err := copyPlan.CandidateBytes(); err != nil || !bytes.Equal(b, before) {
		t.Fatal("immutable copy lost private data")
	}
}

func TestPreparationRefusesInvalidInputBeforeAcquiringEntropy(t *testing.T) {
	for _, change := range []func(*[]byte, *naspolicy.Config, *string){
		func(b *[]byte, c *naspolicy.Config, id *string) { *b = nil },
		func(b *[]byte, c *naspolicy.Config, id *string) { *b = []byte("PRIVATE invalid") },
		func(b *[]byte, c *naspolicy.Config, id *string) {
			*b = bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes+1)
		},
		func(b *[]byte, c *naspolicy.Config, id *string) { *id = "PRIVATE" },
		func(b *[]byte, c *naspolicy.Config, id *string) { *id = strings.Repeat("0", 32) },
		func(b *[]byte, c *naspolicy.Config, id *string) { c.Revision = 7 },
		func(b *[]byte, c *naspolicy.Config, id *string) { c.Revision = 9 },
		func(b *[]byte, c *naspolicy.Config, id *string) { c.FileServices.NFS.VolumeRevision = 9 },
		func(b *[]byte, c *naspolicy.Config, id *string) {
			c.ISCSI.Targets[0].Initiators[0].Grants[0].LUNID = "unknown"
		},
		func(b *[]byte, c *naspolicy.Config, id *string) {
			*b = policy(t, math.MaxUint64)
			*c = nextPolicy(t, 1)
		},
	} {
		base, next, id := policy(t, 7), nextPolicy(t, 8), installation
		change(&base, &next, &id)
		calls := 0
		p, err := prepare(id, base, next, func(b []byte) (int, error) { calls++; return fixedEntropy(b) })
		if err != ErrInvalid || calls != 0 || !reflect.DeepEqual(p, Prepared{}) || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatal("invalid input acquired entropy or retained partial/private data")
		}
	}
}

func TestPreparationEntropyFailureIsRedactedAndNeverRetried(t *testing.T) {
	for _, entropy := range []func([]byte) (int, error){
		nil, func([]byte) (int, error) { return 0, errors.New("PRIVATE entropy") },
		func(b []byte) (int, error) { b[0] = 1; return len(b) - 1, nil },
		func(b []byte) (int, error) { return len(b), nil }, // all-zero IDs refuse
	} {
		calls := 0
		read := entropy
		if read != nil {
			read = func(b []byte) (int, error) { calls++; return entropy(b) }
		}
		p, err := prepare(installation, policy(t, 7), nextPolicy(t, 8), read)
		if err != ErrPreparation || !reflect.DeepEqual(p, Prepared{}) || strings.Contains(err.Error(), "PRIVATE") || calls > 1 {
			t.Fatal("entropy failure retained data, disclosed cause or retried")
		}
	}
}

func TestPreparationBoundsAndMaximumConsecutiveRevision(t *testing.T) {
	base := policy(t, math.MaxUint64-1)
	next := nextPolicy(t, math.MaxUint64)
	base = append(base, bytes.Repeat([]byte(" "), naspolicy.MaxInputBytes-len(base))...)
	p, err := prepare(installation, base, next, fixedEntropy)
	if err != nil {
		t.Fatal(err)
	}
	i, _ := p.Intent()
	b, _ := p.BaseBytes()
	if len(b) != naspolicy.MaxInputBytes || i.value.NextRevision != math.MaxUint64 {
		t.Fatal("inclusive base/revision bound lost")
	}
	if p, err := Prepare(installation, policy(t, 7), nextPolicy(t, 8)); err != nil || !p.valid() {
		t.Fatal("system entropy preparation failed")
	}
}

func TestPreparedPrivacyAndZeroValues(t *testing.T) {
	var zero Prepared
	if b, err := zero.BaseBytes(); b != nil || err != ErrInvalid {
		t.Fatal("zero base")
	}
	if b, err := zero.CandidateBytes(); b != nil || err != ErrInvalid {
		t.Fatal("zero candidate")
	}
	if i, err := zero.Intent(); i != (Intent{}) || err != ErrInvalid {
		t.Fatal("zero intent")
	}
	p, err := Prepare(installation, policy(t, 7), nextPolicy(t, 8))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range []Prepared{zero, p} {
		if _, err := json.Marshal(v); !errors.Is(err, ErrPrivate) {
			t.Fatal("generic serialization")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, installation) || strings.Contains(s, "private-user") || strings.Contains(s, "base:") || !strings.Contains(s, "private") {
				t.Fatal("format disclosure")
			}
		}
	}
	if err := json.Unmarshal([]byte(`{}`), &p); !errors.Is(err, ErrPrivate) {
		t.Fatal("deserialization admitted")
	}
}

func FuzzPreparedOperationPreservesExactPrivateBindings(f *testing.F) {
	f.Add(policy(f, 7))
	f.Add([]byte(`{}`))
	next := nextPolicy(f, 8)
	f.Fuzz(func(t *testing.T, base []byte) {
		if len(base) > 4096 {
			return
		} // explicit units exercise the full656128-byte bound
		p, err := prepare(installation, base, next, fixedEntropy)
		if err != nil {
			if err != ErrInvalid || !reflect.DeepEqual(p, Prepared{}) {
				t.Fatal("partial preparation on invalid input")
			}
			return
		}
		b, _ := p.BaseBytes()
		candidate, _ := p.CandidateBytes()
		intent, _ := p.Intent()
		wire, _ := EncodeIntent(intent)
		if !bytes.Equal(b, base) || intent.value.BaseSHA256 != digest(base) || intent.value.NextSHA256 != digest(candidate) {
			t.Fatal("private byte binding lost")
		}
		for _, tc := range []struct {
			current []byte
			kind    Kind
		}{{b, IntentBaseObserved}, {candidate, PublicationUnconfirmed}} {
			d, err := Match(Evidence{InstallationID: installation, Intent: Slot{Present, wire}, Receipt: Slot{State: Absent}, Current: Slot{Present, tc.current}})
			if err != nil || d.Kind() != tc.kind {
				t.Fatal("preparation fabricated confirmation or lost exact binding")
			}
		}
	})
}
