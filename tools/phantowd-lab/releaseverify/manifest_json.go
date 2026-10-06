// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package releaseverify

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"unicode/utf8"
)

var errManifestStructure = errors.New("invalid release manifest JSON structure")

// The schema is small and fixed: do not recursively accept arbitrary objects
// before encoding/json's case-insensitive struct matching. Exact decoded key
// names are required; valid JSON escaping is not a different field spelling.
func checkManifestStructure(data []byte) error {
	if len(data) == 0 || len(data) > maxManifestSize || !utf8.Valid(data) {
		return errManifestStructure
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.UseNumber()
	if err := scanManifestObject(d, false); err != nil {
		return err
	}
	if _, err := d.Token(); !errors.Is(err, io.EOF) {
		return errManifestStructure
	}
	return nil
}

func scanManifestObject(d *json.Decoder, artifact bool) error {
	start, err := d.Token()
	if err != nil || start != json.Delim('{') {
		return errManifestStructure
	}
	seen := make(map[string]bool)
	for d.More() {
		keyToken, err := d.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || seen[key] {
			return errors.New("duplicate or invalid release manifest field")
		}
		seen[key] = true
		if artifact {
			switch key {
			case "name", "role", "sha256":
				err = scanManifestScalar(d, false)
			case "size_bytes":
				err = scanManifestScalar(d, true)
			default:
				return errManifestStructure
			}
		} else {
			switch key {
			case "format", "product", "release_version", "channel", "model_id", "source_commit", "buildroot_version", "kernel_version", "minimum_installer", "signing_key_id":
				err = scanManifestScalar(d, false)
			case "schema_version":
				err = scanManifestScalar(d, true)
			case "hardware_revisions":
				err = scanManifestArray(d, false)
			case "artifacts":
				err = scanManifestArray(d, true)
			default:
				return errManifestStructure
			}
		}
		if err != nil {
			return err
		}
	}
	end, err := d.Token()
	required := 13
	if artifact {
		required = 4
	}
	if err != nil || end != json.Delim('}') || len(seen) != required {
		return errManifestStructure
	}
	return nil
}

func scanManifestScalar(d *json.Decoder, number bool) error {
	token, err := d.Token()
	if err != nil {
		return errManifestStructure
	}
	if number {
		if _, ok := token.(json.Number); !ok {
			return errManifestStructure
		}
	} else {
		value, ok := token.(string)
		// Every schema1 string has an ASCII semantic grammar. Replacement
		// runes cannot be a valid value; reject decoder surrogate repair here.
		if !ok || strings.ContainsRune(value, utf8.RuneError) {
			return errManifestStructure
		}
	}
	return nil
}

func scanManifestArray(d *json.Decoder, artifacts bool) error {
	start, err := d.Token()
	if err != nil || start != json.Delim('[') {
		return errManifestStructure
	}
	count := 0
	maximum := maxHardwareRevisions
	if artifacts {
		maximum = maxArtifacts
	}
	for d.More() {
		count++
		// The schema fixes both list bounds; no unbounded parser recursion.
		if count > maximum {
			return errManifestStructure
		}
		if artifacts {
			err = scanManifestObject(d, true)
		} else {
			err = scanManifestScalar(d, false)
		}
		if err != nil {
			return err
		}
	}
	end, err := d.Token()
	if err != nil || end != json.Delim(']') || count == 0 {
		return errManifestStructure
	}
	return nil
}
