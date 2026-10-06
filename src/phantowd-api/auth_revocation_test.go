// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestLogoutAllContractAndIssuanceRace(t *testing.T) {
	for _, secure := range []bool{false, true} {
		a, _ := newEmptyTestAuth(t)
		origin, cookie := defaultPublicOrigin, sessionCookieName
		if secure {
			origin = "https://127.0.0.1:8080"
			cookie = hostCookieName
			a.allowedOrigin = origin
		}
		token, session, err := a.sessions.create(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		other, _, _ := a.sessions.create(time.Now())
		epoch := a.sessions.currentEpoch() // captured before a hypothetical KDF completes
		request := func() *http.Request {
			r := authRequest(http.MethodPost, authLogoutAllPath, "")
			if secure {
				r.TLS = &tls.ConnectionState{}
			}
			r.Header.Set("Origin", origin)
			r.AddCookie(&http.Cookie{Name: cookie, Value: token})
			r.Header.Set("X-PhantoWD-CSRF", session.csrf)
			return r
		}
		for _, scenario := range []string{"method", "origin", "csrf", "duplicate-csrf", "body", "query", "duplicate-cookie"} {
			r := request()
			want := http.StatusForbidden
			switch scenario {
			case "method":
				r.Method = http.MethodGet
				want = http.StatusMethodNotAllowed
			case "origin":
				r.Header.Set("Origin", "https://untrusted.invalid")
			case "csrf":
				r.Header.Del("X-PhantoWD-CSRF")
			case "duplicate-csrf":
				r.Header.Add("X-PhantoWD-CSRF", session.csrf)
			case "body":
				r.ContentLength = 1
				want = http.StatusBadRequest
			case "query":
				r.URL.RawQuery = "all=true"
				want = http.StatusBadRequest
			case "duplicate-cookie":
				r.AddCookie(&http.Cookie{Name: cookie, Value: token})
				want = http.StatusUnauthorized
			}
			w := httptest.NewRecorder()
			a.serve(w, r)
			if w.Code != want {
				t.Fatalf("%s got %d want %d", scenario, w.Code, want)
			}
			if _, ok := a.sessions.find(other, time.Now()); !ok {
				t.Fatal("invalid request revoked peer")
			}
		}
		w := httptest.NewRecorder()
		a.serve(w, request())
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"all_panel_sessions_revoked":true`) {
			t.Fatal(w.Code, w.Body.String())
		}
		cookies := w.Result().Cookies()
		if len(cookies) != 1 || cookies[0].Name != cookie || cookies[0].MaxAge != -1 || cookies[0].Secure != secure {
			t.Fatal("unsafe clear cookie", cookies)
		}
		for _, old := range []string{token, other} {
			if _, ok := a.sessions.find(old, time.Now()); ok {
				t.Fatal("peer retained")
			}
		}
		w = httptest.NewRecorder()
		a.issueSession(w, request(), http.StatusOK, epoch)
		if w.Code != http.StatusServiceUnavailable || len(w.Result().Cookies()) != 0 {
			t.Fatal("stale login issued session", w.Code)
		}
		fresh, _, err := a.sessions.create(time.Now())
		if err != nil {
			t.Fatal(err)
		}
		w = httptest.NewRecorder()
		a.serve(w, request())
		if w.Code != http.StatusUnauthorized {
			t.Fatal("replayed revocation accepted")
		}
		if _, ok := a.sessions.find(fresh, time.Now()); !ok {
			t.Fatal("fresh login revoked by old request")
		}
	}
}
