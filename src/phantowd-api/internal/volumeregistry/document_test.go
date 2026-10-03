// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const fixtureUUID = "66666666-7777-8888-9999-aaaaaaaaaaaa"

func fixtureDocument() Document {
	return Document{Format: Format, SchemaVersion: SchemaVersion, Revision: 9,
		Volumes: []shareconfig.Volume{{ID: "explicit-books", FilesystemUUID: fixtureUUID}}}
}

func TestRegistryDocumentStrictEnvelope(t *testing.T) {
	d := fixtureDocument()
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(strings.NewReader(string(data)))
	if err != nil || !reflect.DeepEqual(got, d) {
		t.Fatal("valid claims refused", err)
	}
	for _, input := range []string{"", "{}", "null", string(data) + "{}", strings.Repeat(" ", MaxInputBytes+1),
		strings.Replace(string(data), `"revision":9`, `"revision":9,"revision":10`, 1),
		strings.Replace(string(data), `"revision":9`, `"Revision":9`, 1),
		strings.Replace(string(data), `"revision":9`, `"revision":null`, 1),
		strings.Replace(string(data), `"revision":9,`, "", 1),
		strings.Replace(string(data), `"id":`, `"unknown":`, 1),
		strings.Replace(string(data), `"volumes":[`, `"volumes":[null,`, 1),
		strings.Replace(string(data), `"id":"explicit-books"`, `"id":"\ud800"`, 1)} {
		if got, err := Decode(strings.NewReader(input)); err != ErrObservation || !reflect.DeepEqual(got, Document{}) {
			t.Fatal("invalid envelope produced claims")
		}
	}
	if _, err := Decode(nil); err != ErrObservation {
		t.Fatal("nil reader accepted")
	}
}

func TestRegistryDocumentConstructedBounds(t *testing.T) {
	for _, kind := range []string{"format", "schema", "revision", "nil", "id", "uuid", "duplicate-id", "duplicate-uuid", "excess"} {
		t.Run(kind, func(t *testing.T) {
			d := fixtureDocument()
			switch kind {
			case "format":
				d.Format = shareconfig.Format
			case "schema":
				d.SchemaVersion++
			case "revision":
				d.Revision = 0
			case "nil":
				d.Volumes = nil
			case "id":
				d.Volumes[0].ID = "../bay1"
			case "uuid":
				d.Volumes[0].FilesystemUUID = shareconfig.FilesystemUUID(strings.ToUpper(fixtureUUID))
			case "duplicate-id":
				d.Volumes = append(d.Volumes, shareconfig.Volume{ID: d.Volumes[0].ID, FilesystemUUID: "11111111-2222-3333-4444-555555555555"})
			case "duplicate-uuid":
				d.Volumes = append(d.Volumes, shareconfig.Volume{ID: "other", FilesystemUUID: fixtureUUID})
			case "excess":
				for i := 0; i < shareconfig.MaxVolumes; i++ {
					d.Volumes = append(d.Volumes, shareconfig.Volume{ID: shareconfig.VolumeID(fmt.Sprintf("v%d", i)), FilesystemUUID: shareconfig.FilesystemUUID(fmt.Sprintf("%08x-2222-3333-4444-555555555555", i+1))})
				}
			}
			if d.Validate() != ErrObservation {
				t.Fatal("invalid constructed claims accepted")
			}
		})
	}
	d := fixtureDocument()
	d.Volumes = []shareconfig.Volume{}
	if d.Validate() != nil {
		t.Fatal("explicit empty registry refused")
	}
	for i := 0; i < shareconfig.MaxVolumes; i++ {
		d.Volumes = append(d.Volumes, shareconfig.Volume{ID: shareconfig.VolumeID(fmt.Sprintf("v%d", i)), FilesystemUUID: shareconfig.FilesystemUUID(fmt.Sprintf("%08x-2222-3333-4444-555555555555", i+1))})
	}
	if d.Validate() != nil {
		t.Fatal("exact volume limit refused")
	}
}

func TestRegistryClaimsCannotForgeProtectedSnapshot(t *testing.T) {
	s := Snapshot{}
	if _, err := s.Claims(); err != ErrObservation {
		t.Fatal("zero snapshot trusted")
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("snapshot serialized")
	}
	if err := json.Unmarshal([]byte(`{}`), &s); err == nil {
		t.Fatal("snapshot decoded")
	}
	// Package-local fixture checks ownership without adding a public constructor.
	s = Snapshot{document: fixtureDocument(), observed: true}
	d, err := s.Claims()
	if err != nil {
		t.Fatal(err)
	}
	d.Volumes[0].ID = "mutated"
	next, err := s.Claims()
	if err != nil || next.Volumes[0].ID != "explicit-books" {
		t.Fatal("caller mutated trusted snapshot")
	}
}
