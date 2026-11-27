// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"strings"
	"testing"
)

func TestRC0ServiceIdentityRangeRequiresExactAllocation(t *testing.T) {
	allocation, err := decodeRC0ServiceIdentityRange(strings.NewReader(`{"first_id":23000,"last_id":23010}`))
	if err != nil || allocation.First != 23000 || allocation.Last != 23010 {
		t.Fatalf("explicit allocation was refused: %v", err)
	}
	for _, invalid := range []string{
		`{"first_id":23000}`,
		`{"first_id":23000,"last_id":null}`,
		`{"first_id":23000,"first_id":23000,"last_id":23010}`,
		`{"first_id":23000,"last_id":23010,"state":"/elsewhere"}`,
		`{"first_id":23010,"last_id":23000}`,
	} {
		if _, err := decodeRC0ServiceIdentityRange(strings.NewReader(invalid)); !errors.Is(err, errRC0Review) {
			t.Fatalf("invalid allocation was accepted: %s", invalid)
		}
	}
}
