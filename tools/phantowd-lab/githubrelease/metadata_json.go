// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package githubrelease

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var errReleaseStructure = errors.New("invalid GitHub release metadata structure")

// GitHub metadata is extensible, unlike our signed manifest. Ignore additional
// fields, but never let duplicate keys or case aliases select the values used
// for release/asset admission. The fixed assets roster is bounded before decode.
func checkReleaseStructure(data []byte) error {
	if len(data) == 0 || len(data) > maxReleaseJSON || !utf8.Valid(data) {
		return errReleaseStructure
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanReleaseObject(d, false); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errReleaseStructure
	}
	return nil
}

func scanReleaseObject(d *json.Decoder, asset bool) error {
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errReleaseStructure
	}
	known := []string{"id", "tag_name", "draft", "prerelease", "immutable", "assets"}
	if asset {
		known = []string{"id", "name", "size", "url", "state"}
	}
	seen := make(map[string]bool)
	for d.More() {
		token, err := d.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return errReleaseStructure
		}
		seen[key] = true
		isKnown := false
		for _, name := range known {
			if key != name && strings.EqualFold(key, name) {
				return errReleaseStructure
			}
			isKnown = isKnown || key == name
		}
		if !asset && key == "assets" {
			err = scanReleaseAssets(d)
		} else if isKnown {
			err = scanReleaseScalar(d, key)
		} else {
			var unused json.RawMessage
			err = d.Decode(&unused)
		}
		if err != nil {
			return errReleaseStructure
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim('}') {
		return errReleaseStructure
	}
	for _, name := range known {
		if !seen[name] {
			return errReleaseStructure
		}
	}
	return nil
}

func scanReleaseScalar(d *json.Decoder, key string) error {
	token, err := d.Token()
	if err != nil {
		return errReleaseStructure
	}
	switch key {
	case "id", "size":
		if _, ok := token.(json.Number); !ok {
			return errReleaseStructure
		}
	case "draft", "prerelease", "immutable":
		if _, ok := token.(bool); !ok {
			return errReleaseStructure
		}
	default:
		value, ok := token.(string)
		if !ok || strings.ContainsRune(value, utf8.RuneError) {
			return errReleaseStructure
		}
	}
	return nil
}

func scanReleaseAssets(d *json.Decoder) error {
	start, err := d.Token()
	if err != nil || start != json.Delim('[') {
		return errReleaseStructure
	}
	count := 0
	for d.More() {
		count++
		if count > maxReleaseAssets || scanReleaseObject(d, true) != nil {
			return errReleaseStructure
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') {
		return errReleaseStructure
	}
	return nil
}
