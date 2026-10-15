// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package vendorupdate

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

// The stock merger copies a per-unit 64-byte field labelled "key" to 0x100.
// Its serial-derived source does not establish cryptographic key semantics.
// These are generated sentinels, not captured device identities or keys.
// Keeping that slot opaque must apply to rejected inputs as well as success.
func TestInspectRescueDoesNotDiscloseOpaqueKeyOrMACs(t *testing.T) {
	const first = "02:11:22:33:44:55"
	const second = "06:12:23:34:45:56"
	key := strings.Repeat("synthetic-key-", 5)[:64]
	tests := []struct {
		name      string
		mutate    func([]byte) []byte
		wantValid bool
		wantErr   bool
	}{
		{name: "valid", wantValid: true},
		{
			name: "opaque encryption flag",
			mutate: func(data []byte) []byte {
				data[0x31] = 1
				return data
			},
			wantValid: true,
		},
		{
			name: "wrong magic",
			mutate: func(data []byte) []byte {
				data[0x32] ^= 1
				return data
			},
		},
		{
			name: "wrong selector",
			mutate: func(data []byte) []byte {
				data[0x3e] = 1
				return data
			},
		},
		{
			name: "duplicate MAC",
			mutate: func(data []byte) []byte {
				copy(data[0x1c:0x30], data[:20])
				return data
			},
		},
		{
			name: "corrupt payload",
			mutate: func(data []byte) []byte {
				data[RescueHeaderSize] ^= 1
				return data
			},
		},
		{
			name: "short header",
			mutate: func(data []byte) []byte {
				return data[:RescueHeaderSize-1]
			},
			wantErr: true,
		},
		{
			name: "short payload",
			mutate: func(data []byte) []byte {
				return data[:len(data)-1]
			},
			wantErr: true,
		},
		{
			name: "empty declared payload",
			mutate: func(data []byte) []byte {
				binary.LittleEndian.PutUint32(data[0x14:], 0)
				return data
			},
			wantErr: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fixture := syntheticRescue(first, second)
			copy(fixture[0x100:0x140], key)
			if tt.mutate != nil {
				fixture = tt.mutate(fixture)
			}
			before := bytes.Clone(fixture)
			report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
			if (err != nil) != tt.wantErr || report.Valid != tt.wantValid {
				t.Fatal("unexpected inspection outcome")
			}
			if !report.IdentityRedacted {
				t.Fatal("inspection did not declare identity redaction")
			}
			encoded, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			outputs := []string{string(encoded), fmt.Sprintf("%+v", report)}
			if err != nil {
				outputs = append(outputs, err.Error())
			}
			for _, output := range outputs {
				for _, private := range []string{first, second, key, key[:16], key[48:]} {
					if strings.Contains(output, private) {
						t.Fatal("inspection disclosed a private fixture sentinel")
					}
				}
			}
			if !bytes.Equal(fixture, before) {
				t.Fatal("inspection modified its input")
			}
		})
	}
}

func TestInspectRescueKeepsPerUnitKeyOpaque(t *testing.T) {
	fixture := syntheticRescue("02:11:22:33:44:55", "06:12:23:34:45:56")
	var previous []byte
	for _, marker := range []byte{0, 'A', 'B', 0xff} {
		copy(fixture[0x100:0x140], bytes.Repeat([]byte{marker}, 64))
		report, err := InspectRescueImage(bytes.NewReader(fixture), int64(len(fixture)))
		if err != nil || !report.Valid {
			t.Fatal("opaque slot changed structural inspection")
		}
		encoded, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && !bytes.Equal(encoded, previous) {
			t.Fatal("opaque slot changed the public report")
		}
		previous = encoded
	}
}
