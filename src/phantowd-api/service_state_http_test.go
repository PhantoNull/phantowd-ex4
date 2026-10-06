// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func serviceConfigFixture(revision uint64) fileservice.Config {
	return fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: revision,
		Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: revision, Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
		NFS:    nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: revision, VolumeRevision: revision, Exports: []nfsconfig.Export{}}}
}

func serviceWriteRequest(auth *authController, cookie *http.Cookie, c fileservice.Config) *http.Request {
	data, _ := json.Marshal(c)
	r := authRequest(http.MethodPut, serviceStatePath, string(data))
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(cookie)
	_, session, _ := auth.sessions.sessionFromRequest(r, time.Now())
	r.Header.Set("X-PhantoWD-CSRF", session.csrf)
	return r
}

func TestServiceStateWriteBoundary(t *testing.T) {
	auth, cookie := newTestAuth(t)
	for _, spec := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"valid", func(*http.Request) {}, 200},
		{"utf8", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, 200},
		{"no auth", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"no origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"wrong host", func(r *http.Request) { r.Host = "evil.invalid" }, 403},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 403},
		{"double origin", func(r *http.Request) { r.Header.Add("Origin", defaultPublicOrigin) }, 403},
		{"no csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{"wrong csrf", func(r *http.Request) { r.Header.Set("X-PhantoWD-CSRF", "invalid") }, 403},
		{"double csrf", func(r *http.Request) { r.Header.Add("X-PhantoWD-CSRF", r.Header.Get("X-PhantoWD-CSRF")) }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "apply=true" }, 400},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{"type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{"charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }, 400},
		{"type twice", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400},
		{"known size", func(r *http.Request) { r.ContentLength = fileservice.MaxConfigBytes + 1 }, 413},
		{"chunked size", func(r *http.Request) {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", fileservice.MaxConfigBytes+1)))
		}, 413},
		{"bad JSON", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"private-value":true}`)) }, 422},
		{"cancelled", func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}, 400},
		{"delete", func(r *http.Request) { r.Method = http.MethodDelete }, 405},
	} {
		t.Run(spec.name, func(t *testing.T) {
			calls := 0
			backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { t.Fatal("unexpected read"); return nil, nil }, commit: func(expected uint64, c fileservice.Config) error {
				calls++
				if expected != 0 || c.Revision != 1 {
					t.Fatal("wrong CAS")
				}
				return nil
			}}
			h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
			r := serviceWriteRequest(auth, cookie, serviceConfigFixture(1))
			spec.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != spec.status || (calls == 1) != (spec.status == 200) {
				t.Fatal(w.Code, calls, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || strings.Contains(w.Body.String(), "private-value") {
				t.Fatal("unsafe reply")
			}
			if w.Code == 200 {
				var reply map[string]any
				if json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply["saved"] != true || reply["applied"] != false || reply["activation_available"] != false || reply["runtime_validated"] != false {
					t.Fatal(w.Body.String())
				}
			}
		})
	}
}

func TestServiceStateReadAndErrors(t *testing.T) {
	auth, cookie := newTestAuth(t)
	for _, spec := range []struct {
		name    string
		backend *serviceStateBackend
		status  int
		code    string
	}{
		{"disabled", nil, 503, "service_configuration_not_configured"},
		{"incomplete", &serviceStateBackend{load: func() (*fileservice.Config, error) { return nil, nil }}, 503, "service_configuration_not_configured"},
		{"uninitialized", &serviceStateBackend{load: func() (*fileservice.Config, error) { return nil, nil }, commit: func(uint64, fileservice.Config) error { return nil }}, 200, ""},
		{"invalid", &serviceStateBackend{load: func() (*fileservice.Config, error) { return &fileservice.Config{}, nil }, commit: func(uint64, fileservice.Config) error { return nil }}, 503, "service_configuration_unavailable"},
	} {
		t.Run(spec.name, func(t *testing.T) {
			h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, spec.backend)
			r := shareReadRequest(cookie)
			r.URL.Path = serviceStatePath
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != spec.status {
				t.Fatal(w.Code, w.Body.String())
			}
			if spec.code != "" && !strings.Contains(w.Body.String(), spec.code) {
				t.Fatal(w.Body.String())
			}
			if w.Code == 200 {
				var reply serviceStateResponse
				if json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Initialized || reply.Configuration != nil {
					t.Fatal("absence not preserved")
				}
			}
		})
	}
	for _, spec := range []struct {
		err    error
		status int
		code   string
	}{
		{errServiceStateConflict, 409, "service_configuration_conflict"},
		{errServiceStateUncertain, 503, "service_configuration_reconciliation_required"},
		{errors.New("private path"), 503, "service_configuration_unavailable"},
	} {
		backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { return nil, spec.err }, commit: func(uint64, fileservice.Config) error { return spec.err }}
		h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, serviceWriteRequest(auth, cookie, serviceConfigFixture(1)))
		if w.Code != spec.status || !strings.Contains(w.Body.String(), spec.code) || strings.Contains(w.Body.String(), "private") {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}

func TestServiceStateReadBoundary(t *testing.T) {
	auth, cookie := newTestAuth(t)
	for _, spec := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"no origin", func(*http.Request) {}, 200},
		{"matching origin", func(r *http.Request) { r.Header.Set("Origin", defaultPublicOrigin) }, 200},
		{"no session", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"foreign host", func(r *http.Request) { r.Host = "foreign.invalid" }, 403},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "http://foreign.invalid") }, 403},
		{"duplicate origin", func(r *http.Request) {
			r.Header.Add("Origin", defaultPublicOrigin)
			r.Header.Add("Origin", defaultPublicOrigin)
		}, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "revision=1" }, 400},
		{"body", func(r *http.Request) { r.ContentLength = 1; r.Body = io.NopCloser(strings.NewReader("x")) }, 400},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		{"post", func(r *http.Request) { r.Method = http.MethodPost }, 405},
		{"head", func(r *http.Request) { r.Method = http.MethodHead }, 405},
	} {
		t.Run(spec.name, func(t *testing.T) {
			calls := 0
			backend := &serviceStateBackend{load: func() (*fileservice.Config, error) {
				calls++
				c := serviceConfigFixture(7)
				return &c, nil
			}, commit: func(uint64, fileservice.Config) error { t.Fatal("GET attempted commit"); return nil }}
			h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
			r := shareReadRequest(cookie)
			r.URL.Path = serviceStatePath
			spec.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != spec.status || (calls == 1) != (spec.status == 200) {
				t.Fatal(w.Code, calls)
			}
			if spec.status == 200 {
				var reply serviceStateResponse
				if json.Unmarshal(w.Body.Bytes(), &reply) != nil || !reply.Initialized || reply.Configuration == nil || reply.Configuration.Revision != 7 || reply.Applied || reply.RuntimeValidated || reply.ActivationAvailable {
					t.Fatal("invalid initialized response")
				}
			}
		})
	}
}

func TestServiceStateGateAndAuthRecheck(t *testing.T) {
	auth, cookie := newTestAuth(t)
	entered, release := make(chan struct{}), make(chan struct{})
	backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { close(entered); <-release; return nil, nil }, commit: func(uint64, fileservice.Config) error { t.Fatal("unexpected commit"); return nil }}
	h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	r := shareReadRequest(cookie)
	r.URL.Path = serviceStatePath
	done := make(chan struct{})
	go func() { defer close(done); h.ServeHTTP(httptest.NewRecorder(), r) }()
	defer func() { close(release); <-done }()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("read did not enter")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, serviceWriteRequest(auth, cookie, serviceConfigFixture(1)))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("write queued behind read")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", defaultPublicOrigin+"/healthz", nil))
	if w.Code != 200 {
		t.Fatal("health blocked")
	}
	// Expire the account during body reading; the initial authorization passed.
	r = serviceWriteRequest(auth, cookie, serviceConfigFixture(1))
	r.Body = &callbackBody{ReadCloser: r.Body, callback: func() { _ = auth.accounts.Close() }}
	h = newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatal("auth not rechecked", w.Code)
	}
}

type callbackBody struct {
	io.ReadCloser
	callback func()
}

func (b *callbackBody) Read(p []byte) (int, error) {
	if b.callback != nil {
		b.callback()
		b.callback = nil
	}
	return b.ReadCloser.Read(p)
}

func TestServiceStateOptions(t *testing.T) {
	for _, address := range []string{"0.0.0.0:8080", "[::]:8080", "192.0.2.10:8080", "bad"} {
		if validateServiceStateOptions("/state", "", apiTransportConfig{Address: address}) == nil {
			t.Fatal("nonloopback accepted", address)
		}
	}
	if validateServiceStateOptions("/state", "/legacy", apiTransportConfig{Address: defaultListenAddress}) == nil {
		t.Fatal("two authorities accepted")
	}
	if validateServiceStateOptions("/state", "", apiTransportConfig{Address: defaultListenAddress}) != nil {
		t.Fatal("loopback refused")
	}
}
