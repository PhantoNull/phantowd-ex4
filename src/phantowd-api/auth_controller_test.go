// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func newEmptyTestAuth(t *testing.T) (*authController, *accountStore) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	accounts := openTestAccountStore(t, dir)
	return newAuthController(accounts, defaultPublicOrigin), accounts
}

func authRequest(method, path, body string) *http.Request {
	request := loopbackRequest(method, path, strings.NewReader(body))
	if method == http.MethodPost && body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Origin", defaultPublicOrigin)
	return request
}

func TestFirstAccountSetupProtectsDiagnostics(t *testing.T) {
	auth, _ := newEmptyTestAuth(t)
	var collectorCalls int
	handler := newHandler(func() (systemSnapshot, error) {
		collectorCalls++
		return collectSystem(fixtureProc(), time.Now())
	}, nil, auth)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, loopbackRequest(http.MethodGet, authStatusPath, nil))
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"setup_required":true`) {
		t.Fatalf("first-boot status wrong: status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, loopbackRequest(http.MethodGet, "/api/v1/system", nil))
	if response.Code != http.StatusUnauthorized || collectorCalls != 0 {
		t.Fatalf("diagnostics were available before setup: status=%d collector_calls=%d", response.Code, collectorCalls)
	}

	body, _ := json.Marshal(setupRequest{Username: "nas-admin", Password: testAdminPassword})
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, authRequest(http.MethodPost, authSetupPath, string(body)))
	if response.Code != http.StatusCreated || len(response.Result().Cookies()) != 1 {
		t.Fatalf("first-account setup failed: status=%d body=%s", response.Code, response.Body.String())
	}
	cookie := response.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/" || cookie.Domain != "" {
		t.Fatalf("unsafe QEMU-loopback cookie: %+v", cookie)
	}
	response = httptest.NewRecorder()
	request := loopbackRequest(http.MethodGet, authStatusPath, nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"authenticated":true`) || strings.Contains(response.Body.String(), testAdminPassword) {
		t.Fatalf("authenticated status wrong: status=%d body=%s", response.Code, response.Body.String())
	}
	response = httptest.NewRecorder()
	handler.ServeHTTP(response, authRequest(http.MethodPost, authSetupPath, string(body)))
	if response.Code != http.StatusConflict {
		t.Fatalf("second administrator setup returned status=%d, want conflict", response.Code)
	}
}

func TestLoginLogoutCSRFAndSessionRevocation(t *testing.T) {
	auth, accounts := newEmptyTestAuth(t)
	if err := accounts.setup(context.Background(), "nas-admin", testAdminPassword); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(nil, nil, auth)
	body, _ := json.Marshal(loginRequest{Username: "nas-admin", Password: testAdminPassword})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authRequest(http.MethodPost, authLoginPath, string(body)))
	if response.Code != http.StatusOK {
		t.Fatalf("login failed: status=%d body=%s", response.Code, response.Body.String())
	}
	cookie := response.Result().Cookies()[0]
	response = httptest.NewRecorder()
	request := authRequest(http.MethodPost, authLoginPath, string(body))
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 {
		t.Fatalf("session renewal failed: status=%d body=%s", response.Code, response.Body.String())
	}
	rotatedCookie := response.Result().Cookies()[0]
	response = httptest.NewRecorder()
	request = loopbackRequest(http.MethodGet, authSessionPath, nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("old session remained valid after login rotation: %d", response.Code)
	}
	cookie = rotatedCookie

	response = httptest.NewRecorder()
	request = loopbackRequest(http.MethodGet, authSessionPath, nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("session endpoint failed: status=%d", response.Code)
	}
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &session); err != nil || session.CSRFToken == "" {
		t.Fatalf("CSRF token missing: %s err=%v", response.Body.String(), err)
	}

	response = httptest.NewRecorder()
	request = authRequest(http.MethodPost, authLogoutPath, "")
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("logout without CSRF token returned %d", response.Code)
	}
	response = httptest.NewRecorder()
	request = authRequest(http.MethodPost, authLogoutPath, "")
	request.AddCookie(cookie)
	request.Header.Set("X-PhantoWD-CSRF", session.CSRFToken)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || len(response.Result().Cookies()) != 1 || response.Result().Cookies()[0].MaxAge >= 0 {
		t.Fatalf("logout failed to clear session: status=%d", response.Code)
	}
	response = httptest.NewRecorder()
	request = loopbackRequest(http.MethodGet, "/api/v1/system", nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("revoked cookie still authenticated: status=%d", response.Code)
	}
}

func TestAuthRejectsCrossOriginAndMalformedRequests(t *testing.T) {
	auth, accounts := newEmptyTestAuth(t)
	handler := newHandler(nil, nil, auth)
	body := `{"username":"nas-admin","password":"` + testAdminPassword + `"}`
	request := authRequest(http.MethodPost, authSetupPath, body)
	request.Host = "attacker.example:8080"
	request.Header.Set("Origin", "http://attacker.example:8080")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("DNS-rebinding host was accepted: %d", response.Code)
	}
	if configured, err := accounts.configured(); err != nil || configured {
		t.Fatalf("rejected origin changed account state: configured=%t err=%v", configured, err)
	}

	for _, test := range []struct {
		name, contentType, body, query string
		status                         int
	}{
		{"wrong content type", "text/plain", body, "", http.StatusBadRequest},
		{"unknown field", "application/json", `{"username":"nas-admin","password":"` + testAdminPassword + `","role":"root"}`, "", http.StatusBadRequest},
		{"duplicate field", "application/json", `{"username":"nas-admin","username":"other","password":"` + testAdminPassword + `"}`, "", http.StatusBadRequest},
		{"escaped duplicate field", "application/json", `{"username":"nas-admin","user\u006eame":"other","password":"` + testAdminPassword + `"}`, "", http.StatusBadRequest},
		{"multiple values", "application/json", body + body, "", http.StatusBadRequest},
		{"query", "application/json", body, "?next=/", http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := authRequest(http.MethodPost, authSetupPath+test.query, test.body)
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status=%d, want %d body=%s", response.Code, test.status, response.Body.String())
			}
		})
	}
}

func TestLoginRateLimitAndCredentialErrorAreUniform(t *testing.T) {
	auth, accounts := newEmptyTestAuth(t)
	if err := accounts.setup(context.Background(), "nas-admin", testAdminPassword); err != nil {
		t.Fatal(err)
	}
	handler := newHandler(nil, nil, auth)
	for i := 0; i < loginMaxAttempts; i++ {
		body, _ := json.Marshal(loginRequest{Username: "other-user", Password: testAdminPassword})
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, authRequest(http.MethodPost, authLoginPath, string(body)))
		if response.Code != http.StatusUnauthorized || !strings.Contains(response.Body.String(), "invalid_credentials") {
			t.Fatalf("attempt %d leaked account existence: status=%d body=%s", i+1, response.Code, response.Body.String())
		}
	}
	body, _ := json.Marshal(loginRequest{Username: "nas-admin", Password: "incorrect but sufficiently long passphrase"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authRequest(http.MethodPost, authLoginPath, string(body)))
	if response.Code != http.StatusTooManyRequests || response.Header().Get("Retry-After") != "60" {
		t.Fatalf("login rate limit failed: status=%d retry=%q", response.Code, response.Header().Get("Retry-After"))
	}
}
