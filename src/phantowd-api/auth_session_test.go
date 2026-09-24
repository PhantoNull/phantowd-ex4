// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionLifecycleAndExpiry(t *testing.T) {
	store := newSessionStore()
	now := time.Date(2026, 9, 24, 12, 0, 0, 0, time.UTC)
	token, session, err := store.create(now)
	if err != nil {
		t.Fatal(err)
	}
	if len(token) != 43 || len(session.csrf) != 43 || token == session.csrf {
		t.Fatalf("unexpected token material length or reuse: token=%d csrf=%d", len(token), len(session.csrf))
	}
	if got, ok := store.find(token, now.Add(sessionLifetime-time.Second)); !ok || got.csrf != session.csrf {
		t.Fatal("valid session was not found")
	}
	if _, ok := store.find(token, now.Add(sessionLifetime)); ok {
		t.Fatal("expired session remained valid")
	}
	if validCSRF(session, session.csrf+"x") || !validCSRF(session, session.csrf) {
		t.Fatal("CSRF token comparison did not enforce an exact token")
	}
	store.revoke(token)
	if _, ok := store.find(token, now); ok {
		t.Fatal("revoked session remained valid")
	}
}

func TestSessionCapacityAndCookieFlags(t *testing.T) {
	store := newSessionStore()
	now := time.Now()
	for range maximumSessions {
		if _, _, err := store.create(now); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := store.create(now); err != errSessionCapacity {
		t.Fatalf("session capacity returned %v", err)
	}
	response := httptest.NewRecorder()
	request := httptest.NewRequest("GET", "http://127.0.0.1:8080/", nil)
	store.setCookie(response, request, "random-session-value")
	cookie := response.Result().Cookies()[0]
	if cookie.Name != sessionCookieName || !cookie.HttpOnly || cookie.Secure || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode || cookie.MaxAge != 0 {
		t.Fatalf("unsafe loopback development cookie: %+v", cookie)
	}
	request = httptest.NewRequest("GET", "https://127.0.0.1:8080/", nil)
	request.TLS = &tls.ConnectionState{}
	response = httptest.NewRecorder()
	store.setCookie(response, request, "random-session-value")
	cookie = response.Result().Cookies()[0]
	if cookie.Name != hostCookieName || !cookie.Secure || !cookie.HttpOnly || cookie.Path != "/" || cookie.Domain != "" || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("TLS cookie is missing security attributes: %+v", cookie)
	}
}

func TestValidLoopbackOriginRejectsDNSRebindingHosts(t *testing.T) {
	for _, test := range []struct {
		host, origin string
		valid        bool
	}{
		{"127.0.0.1:8080", "http://127.0.0.1:8080", true},
		{"localhost:8080", "http://localhost:8080", true},
		{"attacker.example:8080", "http://attacker.example:8080", false},
		{"127.0.0.1:8080", "http://attacker.example:8080", false},
		{"127.0.0.1:8080", "https://127.0.0.1:8080", false},
		{"127.0.0.1:8080", "http://127.0.0.1:8080/", false},
	} {
		request := httptest.NewRequest("POST", "http://127.0.0.1:8080/api/v1/auth/login", nil)
		request.Host = test.host
		request.Header.Set("Origin", test.origin)
		if got := validLoopbackOrigin(request); got != test.valid {
			t.Errorf("host=%q origin=%q valid=%t, want %t", test.host, test.origin, got, test.valid)
		}
	}
	tlsRequest := httptest.NewRequest("POST", "https://127.0.0.1:8080/api/v1/auth/login", nil)
	tlsRequest.TLS = &tls.ConnectionState{}
	tlsRequest.Header.Set("Origin", "https://127.0.0.1:8080")
	if !validLoopbackOrigin(tlsRequest) {
		t.Fatal("valid TLS loopback origin rejected")
	}
}
