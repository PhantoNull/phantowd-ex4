// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
)

func assertAccountFailureDeniesHTTP(t *testing.T, auth *authController, cookie *http.Cookie) {
	t.Helper()
	for _, path := range []string{authStatusPath, authSessionPath} {
		r := authRequest(http.MethodGet, path, "")
		r.AddCookie(cookie)
		w := httptest.NewRecorder()
		auth.serve(w, r)
		if w.Code != http.StatusServiceUnavailable || strings.Contains(w.Body.String(), "secret") {
			t.Fatal("unavailable credentials exposed state", w.Code)
		}
	}
	r := authRequest(http.MethodGet, "/api/v1/system", "")
	r.AddCookie(cookie)
	if auth.authorize(r) {
		t.Fatal("old session retained access after storage failure")
	}
	w := httptest.NewRecorder()
	auth.issueSession(w, r, http.StatusOK, auth.sessions.currentEpoch())
	if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
		t.Fatal("issued session after storage failure")
	}
	for _, path := range []string{authSetupPath, authLoginPath} {
		r := authRequest(http.MethodPost, path, `{"username":"test-admin","password":"test-only correct horse battery staple"}`)
		w := httptest.NewRecorder()
		auth.serve(w, r)
		if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
			t.Fatal("unavailable credentials allowed login/reset", w.Code)
		}
	}
}

func TestCredentialBackendFailuresAreLatched(t *testing.T) {
	for _, failure := range []error{errAccountMissing, errAccountUncertain, errors.New("secret private path")} {
		backend := &memoryAccountBackend{}
		accounts := &accountStore{backend: backend}
		if err := accounts.setup(context.Background(), "test-admin", testAdminPassword); err != nil {
			t.Fatal(err)
		}
		auth := newAuthController(accounts, defaultPublicOrigin)
		token, _, err := auth.sessions.create(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		cookie := &http.Cookie{Name: sessionCookieName, Value: token}
		backend.loadErr = failure
		assertAccountFailureDeniesHTTP(t, auth, cookie)
		backend.loadErr = nil // A repaired file alone must not revive old sessions.
		assertAccountFailureDeniesHTTP(t, auth, cookie)
		if _, err := accounts.authenticate(context.Background(), "test-admin", testAdminPassword); err == nil {
			t.Fatal("repaired backend revived a quarantined process")
		}
		accounts.Close()
	}
}

func TestUncertainEnrollmentCannotBeRetriedOrIssueSession(t *testing.T) {
	backend := &memoryAccountBackend{initializeErr: errAccountUncertain}
	accounts := &accountStore{backend: backend}
	auth := newAuthController(accounts, defaultPublicOrigin)
	if err := accounts.setup(context.Background(), "test-admin", testAdminPassword); !errors.Is(err, errAccountUncertain) {
		t.Fatal(err)
	}
	backend.initializeErr = nil
	if err := accounts.setup(context.Background(), "test-admin", testAdminPassword); !errors.Is(err, errAccountUncertain) {
		t.Fatal("uncertain setup retried", err)
	}
	if backend.document.Revision != 0 {
		t.Fatal("quarantine allowed a retry")
	}
	w := httptest.NewRecorder()
	auth.issueSession(w, authRequest(http.MethodPost, authSetupPath, ""), http.StatusCreated, auth.sessions.currentEpoch())
	if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
		t.Fatal("uncertain setup issued session")
	}
}

type changingAccountBackend struct {
	memoryAccountBackend
	loads int
}

func (b *changingAccountBackend) Load() (admincredentials.Document, error) {
	b.loads++
	d, err := b.memoryAccountBackend.Load()
	if b.loads >= 2 {
		d.Revision++
	}
	return d, err
}

func TestLoginRechecksRevisionAfterKDF(t *testing.T) {
	base := &memoryAccountBackend{}
	accounts := &accountStore{backend: base}
	if err := accounts.setup(context.Background(), "test-admin", testAdminPassword); err != nil {
		t.Fatal(err)
	}
	accounts.backend = &changingAccountBackend{memoryAccountBackend: *base}
	if valid, err := accounts.authenticate(context.Background(), "test-admin", testAdminPassword); valid || !errors.Is(err, errAccountUnavailable) {
		t.Fatal("accepted credentials checked against an obsolete revision", err)
	}
}

func TestShortLoginPasswordIsInvalidCredentials(t *testing.T) {
	auth, _ := newTestAuth(t)
	w := httptest.NewRecorder()
	auth.serve(w, authRequest(http.MethodPost, authLoginPath, `{"username":"test-admin","password":"short"}`))
	if w.Code != http.StatusUnauthorized {
		t.Fatal("invalid password reported as service failure", w.Code)
	}
}
