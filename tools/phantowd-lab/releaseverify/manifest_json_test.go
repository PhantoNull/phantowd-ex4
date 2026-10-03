// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"strings"
	"testing"
)

func TestInspectSignedManifestRefusesCaseAliasesBeforePayload(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	for _, mutation := range []struct{ name, old, replacement string }{
		{"root alias", `"model_id":`, `"Model_ID":`},
		{"artifact alias", `"size_bytes":`, `"SIZE_BYTES":`},
		{"case duplicate", `"model_id":"wd-my-cloud-ex4"`, `"model_id":"other-model","MODEL_ID":"wd-my-cloud-ex4"`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			data := []byte(strings.Replace(string(fixture.manifest), mutation.old, mutation.replacement, 1))
			if bytes.Equal(data, fixture.manifest) {
				t.Fatal("regression mutation did not apply")
			}
			verified, report, err := InspectManifest(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(fixture.privateKey, data)),
				fixture.publicKey, "wd-my-cloud-ex4", "board-r1", "nightly")
			if verified != nil || err == nil || !report.SignatureValid || report.Valid || report.ArtifactsChecked {
				t.Fatalf("signed non-exact keys accepted: verified=%t report=%+v err=%v", verified != nil, report, err)
			}
		})
	}
}

func TestManifestStructureRejectsIncompleteWrongShapesAndEncoding(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	var root map[string]json.RawMessage
	if json.Unmarshal(fixture.manifest, &root) != nil {
		t.Fatal("fixture unavailable")
	}
	for key := range root {
		t.Run("missing-"+key, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(root))
			for k, v := range root {
				if k != key {
					copy[k] = v
				}
			}
			data, err := json.Marshal(copy)
			if err != nil || checkManifestStructure(data) == nil {
				t.Fatal("missing required field accepted", err)
			}
		})
		t.Run("null-"+key, func(t *testing.T) {
			copy := make(map[string]json.RawMessage, len(root))
			for k, v := range root {
				copy[k] = v
			}
			copy[key] = json.RawMessage("null")
			data, err := json.Marshal(copy)
			if err != nil || checkManifestStructure(data) == nil {
				t.Fatal("null required field accepted", err)
			}
		})
	}
	for _, mutation := range []struct{ name, old, replacement string }{
		{"artifact missing", `"role":"swupdate-bundle",`, ``},
		{"artifact null", `"name":"rootfs.swu"`, `"name":null`},
		{"wrong object", `"model_id":"wd-my-cloud-ex4"`, `"model_id":{"model_id":"wd-my-cloud-ex4"}`},
		{"wrong array element", `"hardware_revisions":["board-r1"]`, `"hardware_revisions":[["board-r1"]]`},
		{"wrong artifact field", `"role":"swupdate-bundle"`, `"model_id":"wd-my-cloud-ex4"`},
		{"wrong root field", `"model_id":"wd-my-cloud-ex4"`, `"name":"wd-my-cloud-ex4"`},
		{"fraction", `"schema_version":1`, `"schema_version":1.5`},
		{"numeric string", `"schema_version":1`, `"schema_version":"1"`},
		{"unpaired high surrogate", `"model_id":"wd-my-cloud-ex4"`, `"model_id":"wd-\ud800"`},
		{"unpaired low surrogate", `"model_id":"wd-my-cloud-ex4"`, `"model_id":"wd-\udfff"`},
		{"invalid UTF8", `"model_id":"wd-my-cloud-ex4"`, "\"model_id\":\"wd-\xff\""},
		{"unknown secret", `"product":"phantowd"`, `"operator-secret":"fixture-private-value","product":"phantowd"`},
	} {
		t.Run(mutation.name, func(t *testing.T) {
			data := []byte(strings.Replace(string(fixture.manifest), mutation.old, mutation.replacement, 1))
			if bytes.Equal(data, fixture.manifest) {
				t.Fatal("mutation did not apply")
			}
			verified, report, err := InspectManifest(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(fixture.privateKey, data)),
				fixture.publicKey, "wd-my-cloud-ex4", "board-r1", "nightly")
			if verified != nil || err == nil || !report.SignatureValid || report.Valid || report.ArtifactsChecked {
				t.Fatal("malformed signed structure accepted", err)
			}
			if strings.Contains(err.Error(), "operator-secret") || strings.Contains(err.Error(), "fixture-private-value") {
				t.Fatal("structural error echoed input")
			}
		})
	}
	for _, data := range [][]byte{[]byte("null"), []byte("[]"), append(append([]byte{}, fixture.manifest...), []byte(`{}`)...),
		[]byte(strings.Repeat("[", 12000) + strings.Repeat("]", 12000)), bytes.Repeat([]byte(" "), maxManifestSize+1)} {
		if checkManifestStructure(data) == nil {
			t.Fatal("unsupported root/trailing/deep/oversized JSON accepted")
		}
	}
}

func TestManifestStructureAllowsExactEscapedKeysAndReordering(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	for _, replacement := range []string{`"\u006dodel_id":`, `"model\u005fid":`} {
		data := []byte(strings.Replace(string(fixture.manifest), `"model_id":`, replacement, 1))
		report, err := Inspect(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(fixture.privateKey, data)), fixture.publicKey,
			fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
		if err != nil || !report.Valid {
			t.Fatal("canonical decoded escaped key refused", err)
		}
	}
	var root map[string]json.RawMessage
	if json.Unmarshal(fixture.manifest, &root) != nil {
		t.Fatal("fixture unavailable")
	}
	data, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	report, err := Inspect(bytes.NewReader(data), bytes.NewReader(ed25519.Sign(fixture.privateKey, data)), fixture.publicKey,
		fixture.directory, "wd-my-cloud-ex4", "board-r1", "nightly")
	if err != nil || !report.Valid {
		t.Fatal("reordered whitespace fixture refused", err)
	}
}

func TestHashArtifactBytesBoundedExactRead(t *testing.T) {
	for _, size := range []int64{-1, 0, maxArtifactSize + 1} {
		if count, hash, err := hashArtifactBytes(bytes.NewReader([]byte("bytes")), size); err == nil || count != 0 || hash != "" {
			t.Fatal("invalid read bound consumed bytes")
		}
	}
	if _, _, err := hashArtifactBytes(nil, 1); err == nil {
		t.Fatal("nil source accepted")
	}
	for _, test := range []struct {
		contents string
		expected int64
		wantRead int
		valid    bool
	}{
		{"four", 4, 4, true}, {"short", 8, 5, false}, {"longer-than-signed", 4, 5, false},
	} {
		source := bytes.NewReader([]byte(test.contents))
		count, hash, err := hashArtifactBytes(source, test.expected)
		consumed := len(test.contents) - source.Len()
		if (err == nil) != test.valid || consumed != test.wantRead || count != int64(test.wantRead) || (hash != "") != test.valid {
			t.Fatal("unbounded or incorrect payload read", count, consumed, err)
		}
	}
	producer := &countingArtifactProducer{}
	count, hash, err := hashArtifactBytes(producer, 4)
	if err == nil || count != 5 || producer.read != 5 || hash != "" {
		t.Fatal("continuously growing producer was not bounded by signed size plus one", count, producer.read, err)
	}
}

type countingArtifactProducer struct{ read int }

func (r *countingArtifactProducer) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'x'
	}
	r.read += len(p)
	return len(p), nil
}

func TestManifestStructureArtifactRequiredFieldsAndListBounds(t *testing.T) {
	fixture := makeBundle(t, "wd-my-cloud-ex4", []string{"board-r1"}, []byte("payload"))
	var root map[string]json.RawMessage
	if json.Unmarshal(fixture.manifest, &root) != nil {
		t.Fatal("fixture unavailable")
	}
	var entries []map[string]json.RawMessage
	if json.Unmarshal(root["artifacts"], &entries) != nil || len(entries) != 1 {
		t.Fatal("artifact fixture unavailable")
	}
	for key := range entries[0] {
		for _, kind := range []string{"missing", "null"} {
			t.Run(kind+"-"+key, func(t *testing.T) {
				entry := make(map[string]json.RawMessage, len(entries[0]))
				for k, v := range entries[0] {
					if k != key {
						entry[k] = v
					}
				}
				if kind == "null" {
					entry[key] = json.RawMessage("null")
				}
				root["artifacts"], _ = json.Marshal([]map[string]json.RawMessage{entry})
				data, err := json.Marshal(root)
				if err != nil || checkManifestStructure(data) == nil {
					t.Fatal("incomplete artifact structure accepted", err)
				}
			})
		}
	}
	for _, field := range []string{"artifacts", "hardware_revisions"} {
		for _, count := range []int{0, 16, 17} {
			items := make([]json.RawMessage, count)
			for i := range items {
				items[i] = json.RawMessage(`"board-r1"`)
				if field == "artifacts" {
					items[i], _ = json.Marshal(entries[0])
				}
			}
			var fresh map[string]json.RawMessage
			if json.Unmarshal(fixture.manifest, &fresh) != nil {
				t.Fatal("fixture unavailable")
			}
			fresh[field], _ = json.Marshal(items)
			data, err := json.Marshal(fresh)
			if err != nil || (checkManifestStructure(data) == nil) != (count == 16) {
				t.Fatal("structural list bound changed", field, count, err)
			}
		}
	}
	duplicate := []byte(strings.Replace(string(fixture.manifest), `"name":"rootfs.swu"`, `"name":"rootfs.swu","\u006eame":"other.swu"`, 1))
	if checkManifestStructure(duplicate) == nil {
		t.Fatal("escaped artifact duplicate accepted")
	}
}
