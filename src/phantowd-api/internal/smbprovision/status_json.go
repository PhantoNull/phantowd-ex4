// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbprovision

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const MaxStatusBytes = 1 << 20

// Activity contains only totals. Usernames, paths and server IDs stay within
// the status capture. Complete is true only for the packaged full census.
type Activity struct {
	Sessions, Trees, OpenFiles int
	Complete                   bool
}

func ParseActivity(output []byte) (Activity, error) {
	if err := ValidateStatusJSON(output); err != nil {
		return Activity{}, err
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(output, &root); err != nil || root == nil {
		return Activity{}, ErrInvalid
	}
	var version, config string
	if json.Unmarshal(root["version"], &version) != nil || version != "4.22.11" ||
		json.Unmarshal(root["smb_conf"], &config) != nil || config != "/etc/samba/smb.conf" {
		return Activity{}, ErrInvalid
	}
	var result Activity
	for key, count := range map[string]*int{
		"sessions": &result.Sessions, "tcons": &result.Trees, "open_files": &result.OpenFiles,
	} {
		var rows map[string]json.RawMessage
		if err := json.Unmarshal(root[key], &rows); err != nil || rows == nil {
			return Activity{}, ErrInvalid
		}
		*count = len(rows)
	}
	if raw, present := root["phantowd_complete"]; present {
		switch string(raw) {
		case "true":
			result.Complete = true
		case "false":
		default:
			return Activity{}, ErrInvalid
		}
	}
	return result, nil
}

// ValidateStatusJSON rejects duplicate keys, excessive nesting and trailing input.
func ValidateStatusJSON(data []byte) error {
	if len(data) == 0 || len(data) > MaxStatusBytes {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := scanStatusJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return ErrInvalid
	}
	return nil
}

func scanStatusJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return ErrInvalid
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			key, ok := keyToken.(string)
			if err != nil || !ok {
				return ErrInvalid
			}
			if _, exists := seen[key]; exists {
				return ErrInvalid
			}
			seen[key] = struct{}{}
			if err := scanStatusJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return ErrInvalid
		}
	case '[':
		for decoder.More() {
			if err := scanStatusJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}
