//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package iscsicredentials

import (
	"bytes"
	"encoding/json"
	"testing"
)

func TestInspectDocumentReturnsOnlyRevisionAndNeverMutatesInput(t *testing.T) {
	wire, err := json.Marshal(testDocument())
	if err != nil {
		t.Fatal(err)
	}
	before := bytes.Clone(wire)
	if revision, err := InspectDocumentRevision(wire); err != nil || revision != 1 || !bytes.Equal(wire, before) {
		t.Fatal("valid private metadata refused")
	}
	for _, bad := range [][]byte{nil, {}, []byte(`{}`), bytes.Repeat([]byte{' '}, MaxObservedDocumentBytes+1), bytes.Replace(wire, []byte(`"schema_version":1`), []byte(`"schema_version":2`), 1)} {
		if revision, err := InspectDocumentRevision(bad); err != ErrInvalid || revision != 0 {
			t.Fatal("invalid document yielded metadata")
		}
	}
	padded := append(bytes.Clone(wire), bytes.Repeat([]byte{' '}, MaxObservedDocumentBytes-len(wire))...)
	if revision, err := InspectDocumentRevision(padded); err != nil || revision != 1 {
		t.Fatal("inclusive existing byte bound refused")
	}
}
