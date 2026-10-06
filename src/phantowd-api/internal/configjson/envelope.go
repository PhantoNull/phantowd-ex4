// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package configjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"
)

// DecodeEnvelope retains nested raw documents for their own strict decoders.
// It enforces global byte/depth/Unicode/duplicate/null limits and exactly the
// required top-level fields. Nested field semantics are NOT validated here.
func DecodeEnvelope(data []byte, maxBytes, maxDepth int, required ...string) (map[string]json.RawMessage, error) {
	fail := func() (map[string]json.RawMessage, error) {
		return nil, errors.New("invalid configuration envelope")
	}
	if maxBytes <= 0 || maxDepth <= 0 || len(required) == 0 || len(required) > 32 ||
		len(data) > maxBytes || !utf8.Valid(data) || !validSurrogates(data) {
		return fail()
	}
	allowed := make(map[string]bool, len(required))
	for _, name := range required {
		if name == "" || allowed[name] {
			return fail()
		}
		allowed[name] = true
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if scanValue(d, 0, maxDepth, nil) != nil {
		return fail()
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return fail()
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(data, &fields) != nil || len(fields) != len(required) {
		return fail()
	}
	for name := range fields {
		if !allowed[name] {
			return fail()
		}
	}
	return fields, nil
}
