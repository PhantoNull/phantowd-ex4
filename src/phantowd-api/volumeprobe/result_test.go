// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"encoding/json"
	"strings"
	"testing"
)

const validResult = `{"schema_version":1,"status":"ext-metadata","source_kind":"regular-image","filesystem":"ext2","filesystem_uuid":"00112233-4455-6677-8899-aabbccddeeff","mount_performed":false,"compatibility_qualified":false,"activation_allowed":false}`

func TestDecode(t *testing.T) {
	result, err := decode(strings.NewReader(validResult))
	if err != nil || result.Filesystem != "ext2" {
		t.Fatalf("valid response: %+v %v", result, err)
	}
	var fields map[string]any
	if err := json.Unmarshal([]byte(validResult), &fields); err != nil {
		t.Fatal(err)
	}
	for key := range fields {
		t.Run("missing-"+key, func(t *testing.T) {
			copy := make(map[string]any)
			for k, v := range fields {
				if k != key {
					copy[k] = v
				}
			}
			data, _ := json.Marshal(copy)
			if _, err := decode(strings.NewReader(string(data))); err == nil {
				t.Fatal("accepted missing field")
			}
		})
	}
	for _, status := range []string{"other-signature", "unusable-signature", "unidentified", "ambiguous"} {
		data := strings.Replace(validResult, "ext-metadata", status, 1)
		data = strings.Replace(data, `"ext2"`, `""`, 1)
		data = strings.Replace(data, "00112233-4455-6677-8899-aabbccddeeff", "", 1)
		if _, err := decode(strings.NewReader(data)); err != nil {
			t.Fatalf("status %s: %v", status, err)
		}
	}
	for _, data := range []string{
		validResult + validResult, "null", "[]", "{}", strings.Repeat(" ", maxOutput) + validResult,
		strings.Replace(validResult, "ext-metadata", "unidentified", 1),
		strings.Replace(validResult, "ext-metadata", "healthy", 1),
		strings.Replace(validResult, "regular-image", "character-device", 1),
		strings.Replace(validResult, `"ext2"`, `"xfs"`, 1),
		strings.Replace(validResult, "00112233-4455-6677-8899-aabbccddeeff", "00000000-0000-0000-0000-000000000000", 1),
		strings.Replace(validResult, "aabbccddeeff", "AABBCCDDEEFF", 1),
		strings.Replace(validResult, `"activation_allowed":false`, `"activation_allowed":true`, 1),
		strings.Replace(validResult, `"mount_performed":false`, `"mount_performed":null`, 1),
		strings.Replace(validResult, `"schema_version":1`, `"schema_version":1,"schema_version":1`, 1),
		strings.Replace(validResult, `"status"`, `"STATUS"`, 1),
	} {
		if got, err := decode(strings.NewReader(data)); err == nil || got != (Result{}) {
			t.Fatalf("accepted malformed result: %+v %v", got, err)
		}
	}
}

func FuzzDecode(f *testing.F) {
	f.Add(validResult)
	f.Add(`{}`)
	f.Fuzz(func(t *testing.T, input string) {
		result, err := decode(strings.NewReader(input))
		if err != nil && result != (Result{}) {
			t.Fatal("identity escaped failed decode")
		}
		if err == nil && result.Status == "ext-metadata" && !validUUID(result.FilesystemUUID) {
			t.Fatal("invalid accepted UUID")
		}
	})
}
