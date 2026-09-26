// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
)

const changedTestPassword = "test-only new long administrator passphrase"

func passwordRequest(a *authController, cookie *http.Cookie, old, next string) *http.Request {
	body, _ := json.Marshal(passwordChangeRequest{CurrentPassword: old, NewPassword: next})
	r := authRequest(http.MethodPost, authPasswordPath, string(body))
	r.Header.Set("Origin", a.allowedOrigin)
	r.AddCookie(cookie)
	session, _ := a.sessions.find(cookie.Value, time.Now())
	r.Header.Set("X-PhantoWD-CSRF", session.csrf)
	return r
}

func TestPasswordChangeContract(t *testing.T) {
	for _, secure := range []bool{false, true} {
		a, cookie := newTestAuth(t)
		if secure {
			a.allowedOrigin = "https://127.0.0.1:8080"
			cookie.Name = hostCookieName
		}
		peer, _, _ := a.sessions.create(time.Now())
		epoch := a.sessions.currentEpoch()
		request := func() *http.Request {
			r := passwordRequest(a, cookie, testAdminPassword, changedTestPassword)
			if secure {
				r.TLS = &tls.ConnectionState{}
			}
			return r
		}
		for _, scenario := range []string{"method", "origin", "csrf", "duplicate-csrf", "duplicate-cookie", "no-cookie", "query", "encoding", "content-type", "oversized", "unknown-length", "duplicate-field", "case-field", "null", "unknown-field", "trailing", "nesting"} {
			r := request()
			want := http.StatusBadRequest
			switch scenario {
			case "method":
				r.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "origin":
				r.Header.Set("Origin", "https://untrusted.invalid")
				want = http.StatusForbidden
			case "csrf":
				r.Header.Del("X-PhantoWD-CSRF")
				want = http.StatusForbidden
			case "duplicate-csrf":
				r.Header.Add("X-PhantoWD-CSRF", r.Header.Get("X-PhantoWD-CSRF"))
				want = http.StatusForbidden
			case "duplicate-cookie":
				r.AddCookie(cookie)
				want = http.StatusUnauthorized
			case "no-cookie":
				r.Header.Del("Cookie")
				want = http.StatusUnauthorized
			case "query":
				r.URL.RawQuery = "password=hidden"
			case "encoding":
				r.Header.Set("Content-Encoding", "gzip")
			case "content-type":
				r.Header.Add("Content-Type", "application/json")
			case "oversized":
				r.ContentLength = maxPasswordChangeBody + 1
			case "unknown-length":
				r.ContentLength = -1
				r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", maxPasswordChangeBody+1)))
			default:
				body := map[string]string{
					"duplicate-field": `{"current_password":"a","current_password":"b","new_password":"c"}`,
					"case-field":      `{"Current_Password":"a","new_password":"b"}`,
					"null":            `{"current_password":null,"new_password":"b"}`,
					"unknown-field":   `{"current_password":"a","new_password":"b","revision":5}`,
					"trailing":        `{} {}`, "nesting": `{"current_password":{"new_password":"a"}}`,
				}[scenario]
				r.Body = io.NopCloser(strings.NewReader(body))
				r.ContentLength = int64(len(body))
			}
			w := httptest.NewRecorder()
			a.serve(w, r)
			if w.Code != want {
				t.Fatalf("%s secure=%t got %d want %d", scenario, secure, w.Code, want)
			}
			if _, ok := a.sessions.find(peer, time.Now()); !ok {
				t.Fatal("invalid request revoked sessions")
			}
		}
		for _, attempt := range []struct {
			old, next string
			status    int
		}{
			{"incorrect long current password", changedTestPassword, 401}, {testAdminPassword, "short", 422}, {testAdminPassword, testAdminPassword, 422},
		} {
			r := passwordRequest(a, cookie, attempt.old, attempt.next)
			if secure {
				r.TLS = &tls.ConnectionState{}
			}
			w := httptest.NewRecorder()
			a.serve(w, r)
			if w.Code != attempt.status {
				t.Fatal("credential refusal", w.Code)
			}
			if _, ok := a.sessions.find(peer, time.Now()); !ok {
				t.Fatal("invalid password revoked sessions")
			}
		}
		w := httptest.NewRecorder()
		a.serve(w, request())
		if w.Code != 200 || !strings.Contains(w.Body.String(), `"password_changed":true`) {
			t.Fatal("change failed", w.Code)
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != cookie.Name || cookies[0].MaxAge != -1 || cookies[0].Secure != secure {
			t.Fatal("unsafe cookie clearing")
		}
		for _, token := range []string{cookie.Value, peer} {
			if _, ok := a.sessions.find(token, time.Now()); ok {
				t.Fatal("old session retained")
			}
		}
		w = httptest.NewRecorder()
		a.issueSession(w, request(), 200, epoch)
		if w.Code != 503 || len(w.Result().Cookies()) != 0 {
			t.Fatal("old in-flight login escaped revocation")
		}
		if ok, err := a.accounts.authenticate(context.Background(), "test-admin", testAdminPassword); err != nil || ok {
			t.Fatal("old password retained", err)
		}
		if ok, err := a.accounts.authenticate(context.Background(), "test-admin", changedTestPassword); err != nil || !ok {
			t.Fatal("new password failed", err)
		}
		w = httptest.NewRecorder()
		a.serve(w, request())
		if w.Code != 401 {
			t.Fatal("lost-response replay accepted", w.Code)
		}
	}
}

type sessionWithdrawalBackend struct {
	accountBackend
	reads    int
	withdraw func()
}

func (b *sessionWithdrawalBackend) Load() (admincredentials.Document, error) {
	b.reads++
	if b.reads == 3 {
		b.withdraw()
	} // configured -> initial snapshot -> commit recheck
	return b.accountBackend.Load()
}

func TestPasswordChangeRechecksSessionAfterKDF(t *testing.T) {
	for _, scenario := range []string{"logout", "expiry", "csrf-changed"} {
		t.Run(scenario, func(t *testing.T) {
			a, cookie := newTestAuth(t)
			a.accounts.backend = &sessionWithdrawalBackend{accountBackend: a.accounts.backend, withdraw: func() {
				if scenario == "logout" {
					a.sessions.revoke(cookie.Value)
					return
				}
				a.sessions.mu.Lock()
				defer a.sessions.mu.Unlock()
				for key, session := range a.sessions.sessions {
					if scenario == "expiry" {
						session.expiresAt = time.Now().Add(-time.Second)
					} else {
						session.csrf = strings.Repeat("z", 43)
					}
					a.sessions.sessions[key] = session
				}
			}}
			w := httptest.NewRecorder()
			a.serve(w, passwordRequest(a, cookie, testAdminPassword, changedTestPassword))
			want := http.StatusUnauthorized
			if scenario == "csrf-changed" {
				want = http.StatusForbidden
			}
			if w.Code != want {
				t.Fatal("withdrawn authority authorized commit", w.Code)
			}
			if ok, err := a.accounts.authenticate(context.Background(), "test-admin", testAdminPassword); err != nil || !ok {
				t.Fatal("credentials changed after authority withdrawal", err)
			}
		})
	}
}

func TestPasswordChangeBusyAndRateLimit(t *testing.T) {
	a, cookie := newTestAuth(t)
	a.passwordSlot <- struct{}{}
	w := httptest.NewRecorder()
	a.serve(w, passwordRequest(a, cookie, testAdminPassword, changedTestPassword))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("request queued while busy")
	}
	<-a.passwordSlot
	for i := 0; i < loginMaxAttempts; i++ {
		w = httptest.NewRecorder()
		a.serve(w, passwordRequest(a, cookie, "wrong sufficiently long password", changedTestPassword))
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	}
	w = httptest.NewRecorder()
	a.serve(w, passwordRequest(a, cookie, testAdminPassword, changedTestPassword))
	if w.Code != 429 || w.Header().Get("Retry-After") != "60" {
		t.Fatal("missing credential-guess limiter", w.Code)
	}
}

func TestPasswordChangeUncertaintyKeepsSessionsRevoked(t *testing.T) {
	for _, failure := range []error{errAccountUncertain, errors.New("private failure")} {
		backend := &memoryAccountBackend{replaceErr: failure}
		accounts := &accountStore{backend: backend}
		if err := accounts.setup(context.Background(), "test-admin", testAdminPassword); err != nil {
			t.Fatal(err)
		}
		a := newAuthController(accounts, defaultPublicOrigin)
		token, _, _ := a.sessions.create(time.Now())
		peer, _, _ := a.sessions.create(time.Now())
		cookie := &http.Cookie{Name: sessionCookieName, Value: token}
		w := httptest.NewRecorder()
		a.serve(w, passwordRequest(a, cookie, testAdminPassword, changedTestPassword))
		if w.Code != 503 || strings.Contains(w.Body.String(), "private") {
			t.Fatal("unsafe failure response")
		}
		for _, old := range []string{token, peer} {
			if _, ok := a.sessions.find(old, time.Now()); ok {
				t.Fatal("session survived uncertain write")
			}
		}
		backend.replaceErr = nil
		assertAccountFailureDeniesHTTP(t, a, cookie)
	}
}

func TestCancelledPasswordChangeDoesNotRevokeOrCommit(t *testing.T) {
	a, cookie := newTestAuth(t)
	r := passwordRequest(a, cookie, testAdminPassword, changedTestPassword)
	ctx, cancel := context.WithCancel(r.Context())
	cancel()
	r = r.WithContext(ctx)
	w := httptest.NewRecorder()
	a.serve(w, r)
	if w.Code != 503 {
		t.Fatal(w.Code)
	}
	if _, ok := a.sessions.find(cookie.Value, time.Now()); !ok {
		t.Fatal("cancelled change revoked session")
	}
	if ok, err := a.accounts.authenticate(context.Background(), "test-admin", testAdminPassword); err != nil || !ok {
		t.Fatal(err)
	}
}

func TestConcurrentPasswordChangesCommitOnlyOnce(t *testing.T) {
	a, cookie := newTestAuth(t)
	requests := make([]*http.Request, 8)
	for i := range requests {
		requests[i] = passwordRequest(a, cookie, testAdminPassword, changedTestPassword)
	}
	start := make(chan struct{})
	results := make(chan int, len(requests))
	for _, r := range requests {
		go func() { <-start; w := httptest.NewRecorder(); a.serve(w, r); results <- w.Code }()
	}
	close(start)
	wins := 0
	for range requests {
		switch status := <-results; status {
		case 200:
			wins++
		case 401, 503:
		default:
			t.Fatal("unexpected concurrent status", status)
		}
	}
	if wins != 1 {
		t.Fatal("multiple or no password-change commits", wins)
	}
	a.accounts.mu.Lock()
	d, err := a.accounts.loadLocked()
	a.accounts.mu.Unlock()
	if err != nil || d.Revision != 2 {
		t.Fatal("unexpected credential revision", err)
	}
}

func TestPasswordChangeJSONSupportsEscapedByteLimit(t *testing.T) {
	// Only decoding is exercised: controls are JSON-escaped, not logged or
	// claimed to be a recommended password. Two 1024-byte values exceed 2 KiB.
	body, _ := json.Marshal(passwordChangeRequest{CurrentPassword: strings.Repeat("\x01", 1024), NewPassword: strings.Repeat("\x02", 1024)})
	r := authRequest(http.MethodPost, authPasswordPath, string(body))
	w := httptest.NewRecorder()
	var decoded passwordChangeRequest
	if !decodePasswordChange(w, r, &decoded) || len(decoded.NewPassword) != 1024 {
		t.Fatal("valid bounded escaped credentials refused")
	}
}
