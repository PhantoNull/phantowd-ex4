// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package configjson implements the common bounded JSON envelope for desired
// configuration. Callers must additionally validate required fields/semantics.
package configjson

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"unicode/utf8"
)

// Decode rejects duplicate keys, nulls, unknown/non-exact field spellings,
// excess nesting/input and trailing documents. Struct decoding also rejects
// keys used in the wrong object. Errors never echo input or underlying I/O.
func Decode(input io.Reader, target any, maxBytes, maxDepth int, keys map[string]bool) error {
	if maxBytes <= 0 || maxDepth <= 0 {
		return errors.New("invalid JSON limits")
	}
	data, err := io.ReadAll(io.LimitReader(input, int64(maxBytes)+1))
	if err != nil || len(data) > maxBytes || !utf8.Valid(data) || !validSurrogates(data) {
		return errors.New("cannot read bounded UTF-8 configuration")
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanValue(d, 0, maxDepth, keys); err != nil {
		return errors.New("invalid configuration JSON")
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing configuration JSON")
	}
	d = json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if err := d.Decode(target); err != nil {
		return errors.New("invalid configuration fields")
	}
	return nil
}

// encoding/json replaces unpaired UTF-16 surrogate escapes with U+FFFD.
// Configuration paths must be refused, not silently rewritten in that case.
func validSurrogates(data []byte) bool {
	inString := false
	for i := 0; i < len(data); i++ {
		if data[i] == '"' {
			inString = !inString
			continue
		}
		if !inString || data[i] != '\\' {
			continue
		}
		i++
		if i >= len(data) {
			return false
		}
		if data[i] != 'u' {
			continue
		}
		if i+4 >= len(data) {
			return false
		}
		value, err := strconv.ParseUint(string(data[i+1:i+5]), 16, 16)
		if err != nil {
			return false
		}
		i += 4
		if value >= 0xdc00 && value <= 0xdfff {
			return false
		}
		if value >= 0xd800 && value <= 0xdbff {
			if i+6 >= len(data) || data[i+1] != '\\' || data[i+2] != 'u' {
				return false
			}
			low, err := strconv.ParseUint(string(data[i+3:i+7]), 16, 16)
			if err != nil || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return true
}

func scanValue(d *json.Decoder, depth, maxDepth int, keys map[string]bool) error {
	if depth > maxDepth {
		return errors.New("excessive nesting")
	}
	token, err := d.Token()
	if err != nil {
		return err
	}
	if token == nil {
		return errors.New("null is not supported")
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]bool{}
		for d.More() {
			keyToken, err := d.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok || seen[key] || !keys[key] {
				return errors.New("duplicate or unknown field")
			}
			seen[key] = true
			if err := scanValue(d, depth+1, maxDepth, keys); err != nil {
				return err
			}
		}
	case '[':
		for d.More() {
			if err := scanValue(d, depth+1, maxDepth, keys); err != nil {
				return err
			}
		}
	default:
		return errors.New("unexpected delimiter")
	}
	_, err = d.Token()
	return err
}
