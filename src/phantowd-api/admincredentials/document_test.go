// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package admincredentials

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

// Public synthetic test vectors, not usable enrollment passwords or secrets.
const fixtureVerifier = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const replacementVerifier = "$argon2id$v=19$m=19456,t=2,p=1$AQEBAQEBAQEBAQEBAQEBAQ$AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"

func document() Document {
	return Document{Version: Version, Revision: 1, Admin: Account{Username: "nas-admin", PasswordHash: fixtureVerifier}}
}

func legacyDocument() []byte {
	return []byte(`{"version":1,"admin":{"username":"nas-admin","password_hash":"` + fixtureVerifier + `"}}`)
}

func TestDecodeCanonicalVersions(t *testing.T) {
	d := document()
	data, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for _, input := range [][]byte{data, legacyDocument()} {
		got, err := Decode(bytes.NewReader(input))
		if err != nil || got != d {
			t.Fatal("document conversion failed", err)
		}
	}
	for _, input := range []string{
		"", "null", `{}`, string(data) + "\n", string(data) + `{}`,
		strings.Replace(string(data), `"version":2`, `"version":2,"version":2`, 1),
		strings.Replace(string(data), `"version":2`, `"Version":2`, 1),
		strings.Replace(string(data), `"version":2`, `"version":3`, 1),
		strings.Replace(string(data), `"revision":1`, `"revision":0`, 1),
		strings.Replace(string(data), `"revision":1`, `"revision":null`, 1),
		strings.Replace(string(data), `"revision":1`, `"revision":1.0`, 1),
		strings.Replace(string(data), `"revision":1`, `"revision":18446744073709551616`, 1),
		strings.Replace(string(data), `"revision":1,`, "", 1),
		strings.Replace(string(data), `"admin":`, `"extra":null,"admin":`, 1),
		strings.Replace(string(data), `"nas-admin"`, `"user with spaces"`, 1),
		strings.Replace(string(data), fixtureVerifier, "invalid", 1),
		strings.Replace(string(legacyDocument()), `"version":1`, `"version":1,"revision":1`, 1),
		strings.Replace(string(legacyDocument()), `"username":`, `"username":null,"username":`, 1),
		strings.Repeat("x", MaxBytes+1),
	} {
		if got, err := Decode(strings.NewReader(input)); !errors.Is(err, ErrInvalid) || got != (Document{}) {
			t.Fatal("accepted malformed credential state or returned partial credentials")
		}
	}
	if _, err := Decode(failingReader{}); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func TestUsernameGrammar(t *testing.T) {
	for _, name := range []string{"admin", "NAS.Admin_1-test", strings.Repeat("a", 32)} {
		if !ValidUsername(name) {
			t.Fatal("rejected existing username grammar")
		}
	}
	for _, name := range []string{"", "a/b", "a\\b", "user name", "é", "a\x00", strings.Repeat("a", 33)} {
		if ValidUsername(name) {
			t.Fatal("accepted invalid username")
		}
	}
}

func FuzzDocument(f *testing.F) {
	data, _ := json.Marshal(document())
	f.Add(data)
	f.Add(legacyDocument())
	f.Add([]byte(`{"version":2}`))
	f.Fuzz(func(t *testing.T, input []byte) {
		d, err := Decode(bytes.NewReader(input))
		if err != nil {
			if d != (Document{}) {
				t.Fatal("partial credentials on error")
			}
			return
		}
		if d.Validate() != nil || len(input) > MaxBytes {
			t.Fatal("invalid successful decode")
		}
		canonical, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		again, err := Decode(bytes.NewReader(canonical))
		if err != nil || again != d {
			t.Fatal("non-stable canonical decode")
		}
	})
}
