// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/networkpolicy"
)

const networkPreviewFixture = `{"format":"phantowd-network-policy","schema_version":1,"revision":18446744073709551615,"hostname":"nas-example",
"interfaces":[{"slot":"lan-1","ipv4":{"mode":"static","addresses":["192.0.2.10/16"],"default_route":true,"gateway":"192.0.2.1","metric":100},
"ipv6":{"mode":"static","addresses":["2001:db8:1::10/64"],"default_route":true,"gateway":"fe80::1","metric":100}},
{"slot":"lan-2","ipv4":{"mode":"dhcp","addresses":[],"default_route":true,"metric":200},"ipv6":{"mode":"auto","addresses":[],"default_route":true,"metric":200}}],
"routes":[{"slot":"lan-1","destination":"198.51.100.0/24","gateway":"192.0.2.2","metric":300}],
"dns":{"mode":"automatic","source":"lan-2","servers":[],"search_domains":["example.invalid"]}}`

func networkRequest(auth *authController, cookie *http.Cookie, body string) *http.Request {
	r := previewRequest(auth, cookie, body)
	r.URL.Path = networkPreviewPath
	return r
}

func assertNetworkPreview(t *testing.T, w *httptest.ResponseRecorder) {
	t.Helper()
	var p networkPreview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Format != "phantowd-desired-network-preview" || p.SchemaVersion != 1 ||
		p.Scope != "submitted-desired-policy-only" || p.Revision != "18446744073709551615" || p.Hostname != "nas-example" ||
		p.Saved || p.Applied || p.InterfaceBindingValidated || p.KernelStateValidated || p.ConflictsValidated || p.ReachabilityValidated || p.ActivationAvailable ||
		len(p.Interfaces) != 2 || p.Interfaces[0].IPv4.Addresses[0] != "192.0.2.10/16" || p.Interfaces[0].IPv6.Gateway != "fe80::1" ||
		p.Interfaces[1].IPv4.Mode != "dhcp" || p.Interfaces[1].IPv6.Mode != "auto" || len(p.Routes) != 1 || p.DNS.Source != "lan-2" ||
		len(p.Limitations) != 4 || w.Body.Len() > networkPreviewLimit {
		t.Fatal("desired preview lost fields/precision or gained authority", w.Code)
	}
}

func TestNetworkPreviewHTTPBoundsAndAuth(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h := newHandler(nil, nil, auth) // No collector may be needed for a proposal.
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"valid", func(*http.Request) {}, 200},
		{"no-cookie", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"no-origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"foreign-origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") }, 403},
		{"foreign-host", func(r *http.Request) { r.Host = "foreign.invalid" }, 403},
		{"no-csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{"duplicate-csrf", func(r *http.Request) { r.Header.Add("X-PhantoWD-CSRF", r.Header.Get("X-PhantoWD-CSRF")) }, 403},
		{"wrong-csrf", func(r *http.Request) { r.Header.Set("X-PhantoWD-CSRF", "wrong") }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "apply=true" }, 400},
		{"empty-query", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{"type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{"duplicate-type", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400},
		{"charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }, 400},
		{"declared-size", func(r *http.Request) { r.ContentLength = networkpolicy.MaxInputBytes + 1 }, 413},
		{"get", func(r *http.Request) { r.Method = http.MethodGet }, 405},
		{"put", func(r *http.Request) { r.Method = http.MethodPut }, 405},
		{"canceled", func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}, 408},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := networkRequest(auth, cookie, networkPreviewFixture)
			tc.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("boundary=%s status=%d want=%d", tc.name, w.Code, tc.status)
			}
			if tc.status == 200 {
				assertNetworkPreview(t, w)
			}
		})
	}
	for _, body := range []string{`{}`, `{"PRIVATE":true}`, networkPreviewFixture + `{}`,
		strings.Replace(networkPreviewFixture, `"revision":18446744073709551615`, `"revision":1,"revision":2`, 1),
		strings.Replace(networkPreviewFixture, `"slot":"lan-2"`, `"slot":"eth0"`, 1),
		strings.Replace(networkPreviewFixture, `"metric":200`, `"metric":100`, 1),
		strings.Replace(networkPreviewFixture, `"192.0.2.10/16"`, `"192.0.2.10/16","192.0.2.10/24"`, 1),
	} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, networkRequest(auth, cookie, body))
		if w.Code != 422 || strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal("invalid policy admitted/disclosed")
		}
	}
	for _, extra := range []int{0, 1} {
		body := networkPreviewFixture + strings.Repeat(" ", networkpolicy.MaxInputBytes-len(networkPreviewFixture)+extra)
		r := networkRequest(auth, cookie, body)
		r.ContentLength = -1
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if extra == 0 {
			assertNetworkPreview(t, w)
		} else if w.Code != 413 {
			t.Fatal("stream bound bypassed", w.Code)
		}
	}
}

func TestNetworkPreviewOneBodyRevocationAndNoEffects(t *testing.T) {
	auth, cookie := newTestAuth(t)
	calls := 0
	backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { calls++; return nil, nil }, commit: func(uint64, fileservice.Config) error { calls++; return nil }}
	h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	held := &heldPreviewBody{entered: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(networkPreviewFixture)}
	r := networkRequest(auth, cookie, networkPreviewFixture)
	r.Body = held
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w }()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		close(held.release)
		t.Fatal("body admission not reached")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, networkRequest(auth, cookie, networkPreviewFixture))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		close(held.release)
		<-done
		t.Fatal("queued concurrent preview")
	}
	broken := &failingPreviewBody{}
	r2 := networkRequest(auth, cookie, networkPreviewFixture)
	r2.Header.Del("Cookie")
	r2.Body = broken
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r2)
	if w.Code != 401 || broken.reads != 0 {
		close(held.release)
		<-done
		t.Fatal("read before authentication")
	}
	// Revoke the session while the request is reading; no result may escape.
	auth.sessions.revoke(cookie.Value)
	close(held.release)
	select {
	case w = <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("held preview did not settle")
	}
	if w.Code != 401 || calls != 0 {
		t.Fatal("revocation/effect boundary failed", w.Code, calls)
	}
}
