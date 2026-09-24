// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAccountStoreFirstSetupAndReopen(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := openAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	configured, err := store.configured()
	if err != nil || configured {
		t.Fatalf("initial store configured=%t err=%v", configured, err)
	}
	if err := store.setup(context.Background(), "nas-admin", testAdminPassword); err != nil {
		t.Fatal(err)
	}
	if err := store.setup(context.Background(), "second-admin", testAdminPassword); !errors.Is(err, errAccountConfigured) {
		t.Fatalf("second first-account setup returned %v", err)
	}
	valid, err := store.authenticate(context.Background(), "nas-admin", testAdminPassword)
	if err != nil || !valid {
		t.Fatalf("correct credentials rejected: valid=%t err=%v", valid, err)
	}
	valid, err = store.authenticate(context.Background(), "nas-admin", "a different sufficiently long password")
	if err != nil || valid {
		t.Fatalf("incorrect password accepted: valid=%t err=%v", valid, err)
	}
	valid, err = store.authenticate(context.Background(), "unknown-user", testAdminPassword)
	if err != nil || valid {
		t.Fatalf("unknown user accepted: valid=%t err=%v", valid, err)
	}

	path := filepath.Join(dir, accountFileName)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !privatePermissions(info.Mode(), 0o600) {
		t.Fatalf("account file permissions are not private: %v", info.Mode().Perm())
	}
	reopened, err := openAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	configured, err = reopened.configured()
	if err != nil || !configured {
		t.Fatalf("reopened store configured=%t err=%v", configured, err)
	}
	valid, err = reopened.authenticate(context.Background(), "nas-admin", testAdminPassword)
	if err != nil || !valid {
		t.Fatalf("credentials did not survive store reopen: valid=%t err=%v", valid, err)
	}
}

func TestAccountStateDirectoryRequiresExplicitConfiguration(t *testing.T) {
	if _, err := configuredAccountStateDirectory(""); err == nil {
		t.Fatal("accepted an unspecified account state directory")
	}

	configured := "/run/phantowd-state"
	resolved, err := configuredAccountStateDirectory(configured)
	if err != nil {
		t.Fatalf("rejected explicitly configured account state directory: %v", err)
	}
	if resolved != configured {
		t.Fatalf("resolved state directory %q, want configured value %q", resolved, configured)
	}
}

func TestAccountStoreConcurrentFirstSetupIsSingleWriter(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	first, err := openAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	second, err := openAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	results := make(chan error, 2)
	for _, store := range []*accountStore{first, second} {
		go func(store *accountStore) {
			<-start
			results <- store.setup(context.Background(), "nas-admin", testAdminPassword)
		}(store)
	}
	close(start)
	firstResult, secondResult := <-results, <-results
	if (firstResult == nil) == (secondResult == nil) {
		t.Fatalf("expected exactly one concurrent setup to succeed, got %v and %v", firstResult, secondResult)
	}
	loser := firstResult
	if loser == nil {
		loser = secondResult
	}
	if !errors.Is(loser, errAccountConfigured) {
		t.Fatalf("losing setup returned %v, want already-configured", loser)
	}
	if _, err := openAccountStore(dir); err != nil {
		t.Fatalf("winning setup did not leave a valid account: %v", err)
	}
}

func TestAccountStoreRejectsUnsafeOrInvalidState(t *testing.T) {
	for _, username := range []string{"", "a user", "admin/other", "bad\\name", "é"} {
		if validUsername(username) {
			t.Errorf("accepted invalid username %q", username)
		}
	}
	if !validUsername("nas_admin-1.example") {
		t.Fatal("rejected supported username characters")
	}
	if validSetupPassword("short") || validSetupPassword(string(make([]byte, 1025))) || validSetupPassword(string([]byte{0xff})+strings.Repeat("a", 20)) {
		t.Fatal("accepted an invalid password length or UTF-8 sequence")
	}
	if !validSetupPassword("abcdefghijklmné") {
		t.Fatal("rejected a valid 15-character UTF-8 password")
	}

	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	store, err := openAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.setup(context.Background(), "nas-admin", testAdminPassword); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, accountFileName)
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := openAccountStore(dir); err == nil {
			t.Fatal("opened world-readable credential state")
		}
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(path, []byte(`{"version":2,"admin":{"username":"nas-admin","password_hash":"bad"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openAccountStore(dir); err == nil {
		t.Fatal("opened unsupported/corrupt account state")
	}
}
