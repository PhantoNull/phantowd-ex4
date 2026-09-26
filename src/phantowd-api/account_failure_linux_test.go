// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/passwordhash"
)

func TestMissingCorruptOrPublicAccountNeverReenrolls(t *testing.T) {
	for _, mode := range []string{"missing", "corrupt", "permissions"} {
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			accounts := openTestAccountStore(t, dir)
			if err := accounts.setup(context.Background(), "test-admin", testAdminPassword); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "accounts.json")
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			auth := newAuthController(accounts, defaultPublicOrigin)
			token, _, err := auth.sessions.create(time.Now())
			if err != nil {
				t.Fatal(err)
			}
			cookie := &http.Cookie{Name: sessionCookieName, Value: token}
			switch mode {
			case "missing":
				err = os.Remove(path)
			case "corrupt":
				err = os.WriteFile(path, []byte("{truncated"), 0600)
			case "permissions":
				err = os.Chmod(path, 0644)
			}
			if err != nil {
				t.Fatal(err)
			}
			assertAccountFailureDeniesHTTP(t, auth, cookie)
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(path, 0600); err != nil {
				t.Fatal(err)
			}
			assertAccountFailureDeniesHTTP(t, auth, cookie)
			if err := accounts.Close(); err != nil {
				t.Fatal(err)
			}
			reopened := openTestAccountStore(t, dir)
			if valid, err := reopened.authenticate(context.Background(), "test-admin", testAdminPassword); err != nil || !valid {
				t.Fatal("valid restored state did not reopen", err)
			}
			fresh := newAuthController(reopened, defaultPublicOrigin)
			r := authRequest(http.MethodGet, "/api/v1/system", "")
			r.AddCookie(cookie)
			if fresh.authorize(r) {
				t.Fatal("old cookie survived controller restart")
			}
		})
	}
}

func TestLegacyAccountAdapterRetainsIdentityAndRejectsConcurrentOwner(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	verifier, err := passwordhash.Hash(context.Background(), []byte(testAdminPassword))
	if err != nil {
		t.Fatal(err)
	}
	legacy := struct {
		Version int                      `json:"version"`
		Admin   admincredentials.Account `json:"admin"`
	}{1, admincredentials.Account{Username: "test-admin", PasswordHash: verifier}}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "accounts.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	accounts := openTestAccountStore(t, dir)
	if valid, err := accounts.authenticate(context.Background(), "test-admin", testAdminPassword); err != nil || !valid {
		t.Fatal(err)
	}
	if err := accounts.setup(context.Background(), "other-admin", testAdminPassword); !errors.Is(err, errAccountConfigured) {
		t.Fatal(err)
	}
	if other, err := openAccountStore(dir); !errors.Is(err, errAccountBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("accepted second owner", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || string(after) != string(data) {
		t.Fatal("legacy account was rewritten", err)
	}
}

func TestAccountStorageErrorRedaction(t *testing.T) {
	for _, tc := range []struct{ input, want error }{
		{nil, nil}, {revisionstore.ErrNotInitialized, errAccountMissing},
		{revisionstore.ErrUncertain, errAccountUncertain}, {revisionstore.ErrBusy, errAccountBusy},
		{revisionstore.ErrClosed, errAccountClosed}, {errors.New("private secret path"), errAccountUnavailable},
	} {
		if got := accountStorageError(tc.input); got != tc.want {
			t.Fatal("incorrect error classification")
		}
	}
}
