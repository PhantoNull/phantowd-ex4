// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package configjson

import (
	"strings"
	"testing"
)

func TestUnicodeEscapesAreNotSilentlyRewritten(t *testing.T) {
	for _, value := range []string{`"\uD800"`, `"\uDC00"`, `"\uD800x"`, `"\uD800\u0041"`, `"\uD800\uD800"`, `"\uDC00\uD800"`} {
		var result struct {
			Path string `json:"path"`
		}
		if Decode(strings.NewReader(`{"path":`+value+`}`), &result, 1024, 4, map[string]bool{"path": true}) == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	for value, want := range map[string]string{`"\uD83D\uDC7B"`: "👻", `"\uFFFD"`: "�", `"\\uD800"`: `\uD800`, `"quote\"text"`: `quote"text`} {
		var result struct {
			Path string `json:"path"`
		}
		err := Decode(strings.NewReader(`{"path":`+value+`}`), &result, 1024, 4, map[string]bool{"path": true})
		if err != nil || result.Path != want {
			t.Fatalf("decode %s: %q %v", value, result.Path, err)
		}
	}
}

func TestEnvelopeBoundaries(t *testing.T) {
	for _, data := range []string{`{"path":"a","path":"b"}`, `{"Path":"a"}`, `{"path":null}`, `{"path":"a"} {}`, `{"other":"a"}`, `{"path":"a`, `{"path":"\uD8"}`} {
		var result struct {
			Path string `json:"path"`
		}
		if Decode(strings.NewReader(data), &result, 1024, 4, map[string]bool{"path": true}) == nil {
			t.Fatalf("accepted %s", data)
		}
	}
}
