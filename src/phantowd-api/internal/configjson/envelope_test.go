// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package configjson

import (
	"bytes"
	"strings"
	"testing"
)

func TestRawEnvelopeStrictBoundaries(t *testing.T) {
	valid := []byte(`{"child":{"unknown_to_envelope":[{"number":0}]},"revision":1}`)
	fields, err := DecodeEnvelope(valid, 256, 6, "child", "revision")
	if err != nil || !bytes.Equal(fields["child"], []byte(`{"unknown_to_envelope":[{"number":0}]}`)) {
		t.Fatal("raw child was rewritten", fields, err)
	}
	for _, data := range []string{
		`null`, `[]`, `{}`, `{"child":{},"revision":1,"other":0}`,
		`{"Child":{},"revision":1}`, `{"child":{},"child":{},"revision":1}`,
		`{"child":{"a":0,"a":1},"revision":1}`, `{"child":{"a":null},"revision":1}`,
		`{"child":{},"revision":null}`, `{"child":{"a":"\ud800"},"revision":1}`,
		`{"child":{},"revision":1} {}`, `{"child":{},"revision":1`,
		`{"child":{"a":"` + string([]byte{0xff}) + `"},"revision":1}`,
		`{"child":` + strings.Repeat("[", 8) + `0` + strings.Repeat("]", 8) + `,"revision":1}`,
	} {
		if got, err := DecodeEnvelope([]byte(data), 256, 6, "child", "revision"); err == nil || got != nil {
			t.Fatalf("invalid envelope returned state: %q %v", data, err)
		}
	}
	for _, keys := range [][]string{nil, {"child", "child"}, {""}} {
		if got, err := DecodeEnvelope(valid, 256, 6, keys...); err == nil || got != nil {
			t.Fatal("invalid trusted field contract accepted")
		}
	}
	if got, err := DecodeEnvelope(valid, len(valid)-1, 6, "child", "revision"); got != nil || err == nil {
		t.Fatal("oversize envelope accepted")
	}
	var target struct {
		Child any `json:"child"`
	}
	if Decode(strings.NewReader(`{"child":{}}`), &target, 256, 6, nil) == nil {
		t.Fatal("nil-key envelope scan weakened strict struct decoder")
	}
}
