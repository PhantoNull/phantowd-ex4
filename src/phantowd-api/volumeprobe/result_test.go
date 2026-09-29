// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"encoding/json"
	"strings"
	"testing"
)

const validResult = `{"schema_version":2,"status":"ext-metadata","source_kind":"regular-image","filesystem":"ext2","filesystem_uuid":"00112233-4455-6677-8899-aabbccddeeff","partition_table":"","partition_table_id":"","partitions":[],"mount_performed":false,"compatibility_qualified":false,"activation_allowed":false}`
const validGPTResult = `{"schema_version":2,"status":"other-signature","source_kind":"regular-image","filesystem":"","filesystem_uuid":"","partition_table":"gpt","partition_table_id":"fedcba98-7654-3210-fedc-ba9876543210","partitions":[{"number":1,"start_512b_sectors":34,"size_512b_sectors":16,"uuid":"00112233-4455-6677-8899-aabbccddeeff","type_id":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","extended":false}],"mount_performed":false,"compatibility_qualified":false,"activation_allowed":false}`
const validDOSResult = `{"schema_version":2,"status":"other-signature","source_kind":"regular-image","filesystem":"","filesystem_uuid":"","partition_table":"dos","partition_table_id":"12345678","partitions":[{"number":1,"start_512b_sectors":2048,"size_512b_sectors":512,"uuid":"12345678-01","type_id":"0x83","extended":false},{"number":2,"start_512b_sectors":4096,"size_512b_sectors":2048,"uuid":"12345678-02","type_id":"0x0f","extended":true},{"number":5,"start_512b_sectors":4097,"size_512b_sectors":256,"uuid":"12345678-05","type_id":"0x83","extended":false},{"number":6,"start_512b_sectors":5121,"size_512b_sectors":256,"uuid":"12345678-06","type_id":"0x83","extended":false}],"mount_performed":false,"compatibility_qualified":false,"activation_allowed":false}`

func TestDecodeValidGPTPartitionMetadata(t *testing.T) {
	result, err := decode(strings.NewReader(validGPTResult))
	if err != nil {
		t.Fatalf("valid partition metadata: %v", err)
	}
	if result.PartitionTable == nil || result.PartitionTable.Scheme != "gpt" ||
		result.PartitionTable.ID != "fedcba98-7654-3210-fedc-ba9876543210" ||
		len(result.PartitionTable.Partitions) != 1 ||
		result.PartitionTable.Partitions[0].UUID != "00112233-4455-6677-8899-aabbccddeeff" {
		t.Fatalf("partition identity not retained: %+v", result.PartitionTable)
	}
}

func TestDecodeValidDOSPartitionMetadata(t *testing.T) {
	result, err := decode(strings.NewReader(validDOSResult))
	if err != nil {
		t.Fatalf("valid DOS partition metadata: %v", err)
	}
	if result.PartitionTable == nil || result.PartitionTable.Scheme != "dos" ||
		result.PartitionTable.ID != "12345678" || len(result.PartitionTable.Partitions) != 4 ||
		!result.PartitionTable.Partitions[1].Extended ||
		result.PartitionTable.Partitions[2].Number != 5 {
		t.Fatalf("DOS partition identity not retained: %+v", result.PartitionTable)
	}
}

func TestDecodeRejectsInconsistentPartitionMetadata(t *testing.T) {
	duplicateUUID := strings.Replace(validGPTResult,
		`],"mount_performed":false`,
		`,{"number":2,"start_512b_sectors":60,"size_512b_sectors":16,"uuid":"00112233-4455-6677-8899-aabbccddeeff","type_id":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","extended":false}],"mount_performed":false`, 1)
	overlap := strings.Replace(validGPTResult,
		`],"mount_performed":false`,
		`,{"number":2,"start_512b_sectors":40,"size_512b_sectors":16,"uuid":"11112233-4455-6677-8899-aabbccddeeff","type_id":"c12a7328-f81f-11d2-ba4b-00a0c93ec93b","extended":false}],"mount_performed":false`, 1)
	for name, data := range map[string]string{
		"duplicate UUID":             duplicateUUID,
		"overlapping GPT partitions": overlap,
		"zero partition number":      strings.Replace(validGPTResult, `"number":1`, `"number":0`, 1),
		"GPT marked extended":        strings.Replace(validGPTResult, `"extended":false`, `"extended":true`, 1),
		"unsupported table":          strings.Replace(validGPTResult, `"partition_table":"gpt"`, `"partition_table":"aix"`, 1),
		"missing array":              strings.Replace(validGPTResult, `"partitions":[{`, `"partitions":null`, 1),
		"table ID with no table":     strings.Replace(validGPTResult, `"partition_table":"gpt"`, `"partition_table":""`, 1),
		"table on unidentified":      strings.Replace(validGPTResult, `"other-signature"`, `"unidentified"`, 1),
		"unknown nested field":       strings.Replace(validGPTResult, `"extended":false`, `"extended":false,"extra":true`, 1),
	} {
		t.Run(name, func(t *testing.T) {
			if result, err := decode(strings.NewReader(data)); err == nil || result != (Result{}) {
				t.Fatalf("accepted inconsistent partition metadata: %+v", result.PartitionTable)
			}
		})
	}
}

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
		strings.Replace(validResult, `"schema_version":2`, `"schema_version":2,"schema_version":2`, 1),
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
