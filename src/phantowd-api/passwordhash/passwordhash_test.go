// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package passwordhash

import (
	"context"
	"strings"
	"testing"
)

func TestHashAndVerify(t *testing.T) {
	ctx := context.Background()
	first, err := Hash(ctx, []byte("test-only passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := Hash(ctx, []byte("test-only passphrase"))
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("independent hashes reused the same salt")
	}
	if !strings.HasPrefix(first, "$argon2id$v=19$m=19456,t=2,p=1$") {
		t.Fatalf("unexpected PHC verifier format: %q", first[:min(len(first), 64)])
	}

	valid, err := Verify(ctx, []byte("test-only passphrase"), first)
	if err != nil || !valid {
		t.Fatalf("correct password rejected: valid=%t err=%v", valid, err)
	}
	valid, err = Verify(ctx, []byte("wrong passphrase"), first)
	if err != nil || valid {
		t.Fatalf("wrong password accepted: valid=%t err=%v", valid, err)
	}
}

func TestVerifyRejectsInvalidPasswordsAndVerifiers(t *testing.T) {
	for _, password := range [][]byte{nil, {}, make([]byte, maxPasswordLength+1)} {
		if _, err := Verify(context.Background(), password, "not a verifier"); err == nil {
			t.Fatalf("Verify(%d-byte password) succeeded", len(password))
		}
	}
	for _, encoded := range []string{
		"",
		"$argon2i$v=19$m=19456,t=2,p=1$AA$AA",
		"$argon2id$v=16$m=19456,t=2,p=1$AA$AA",
		"$argon2id$v=19$m=1,t=2,p=1$AA$AA",
		"$argon2id$v=19$m=65537,t=2,p=1$AA$AA",
		"$argon2id$v=19$m=19456,t=1,p=1$AA$AA",
		"$argon2id$v=19$m=19456,t=5,p=1$AA$AA",
		"$argon2id$v=19$m=19456,t=2,p=0$AA$AA",
		"$argon2id$v=19$m=19456,t=2,p=5$AA$AA",
		"$argon2id$v=19$m=019456,t=2,p=1$AA$AA",
		"$argon2id$v=19$m=19456,p=1,t=2$AA$AA",
		"$argon2id$v=19$m=19456,t=2,p=1$not-base64!$AA",
		"$argon2id$v=19$m=19456,t=2,p=1$AA$AA",
		strings.Repeat("x", maxPHCLength+1),
	} {
		if _, err := Verify(context.Background(), []byte("passphrase"), encoded); err == nil {
			t.Fatalf("Verify accepted invalid verifier %q", encoded)
		}
	}
}

func TestHashRejectsInvalidPasswordLength(t *testing.T) {
	for _, password := range [][]byte{nil, {}, make([]byte, maxPasswordLength+1)} {
		if _, err := Hash(context.Background(), password); err == nil {
			t.Fatalf("Hash(%d-byte password) succeeded", len(password))
		}
	}
}

func FuzzParsePHC(f *testing.F) {
	f.Add("$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	f.Add("")
	f.Add(strings.Repeat("x", maxPHCLength+1))
	f.Fuzz(func(t *testing.T, encoded string) {
		if len(encoded) > maxPHCLength*2 {
			t.Skip()
		}
		p, err := parse(encoded)
		if err == nil && (p.memoryKiB < defaultMemoryKiB || p.memoryKiB > maxMemoryKiB ||
			p.iterations < defaultIterations || p.iterations > maxIterations ||
			p.threads < defaultThreads || p.threads > maxThreads ||
			len(p.salt) < saltLength || len(p.salt) > 32 || len(p.key) != keyLength) {
			t.Fatal("parser returned parameters outside configured bounds")
		}
	})
}
