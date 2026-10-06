// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
)

const emptyFileServiceFixture = `{"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[]}}`

func previewRequest(auth *authController, cookie *http.Cookie, body string) *http.Request {
	r := authRequest(http.MethodPost, fileServicePreviewPath, body)
	r.AddCookie(cookie)
	_, session, _ := auth.sessions.sessionFromRequest(r, time.Now())
	r.Header.Set("X-PhantoWD-CSRF", session.csrf)
	return r
}

func TestFileServicePreviewHTTPBoundary(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h := newHandler(nil, nil, auth)
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
		code   string
	}{
		{"valid", func(*http.Request) {}, 200, ""},
		{"utf8", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=utf-8") }, 200, ""},
		{"logged out", func(r *http.Request) { r.Header.Del("Cookie") }, 401, "authentication_required"},
		{"missing origin", func(r *http.Request) { r.Header.Del("Origin") }, 403, "origin_not_allowed"},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.example") }, 403, "origin_not_allowed"},
		{"wrong host", func(r *http.Request) { r.Host = "evil.example" }, 403, "origin_not_allowed"},
		{"missing csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403, "csrf_validation_failed"},
		{"wrong csrf", func(r *http.Request) { r.Header.Set("X-PhantoWD-CSRF", "wrong") }, 403, "csrf_validation_failed"},
		{"duplicate csrf", func(r *http.Request) { r.Header.Add("X-PhantoWD-CSRF", r.Header.Get("X-PhantoWD-CSRF")) }, 403, "csrf_validation_failed"},
		{"query", func(r *http.Request) { r.URL.RawQuery = "apply=true" }, 400, "invalid_preview_request"},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, 400, "invalid_preview_request"},
		{"gzip", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400, "invalid_preview_request"},
		{"empty encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "") }, 400, "invalid_preview_request"},
		{"text", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400, "invalid_preview_request"},
		{"wrong charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }, 400, "invalid_preview_request"},
		{"extra parameter", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; boundary=x") }, 400, "invalid_preview_request"},
		{"duplicate type", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400, "invalid_preview_request"},
		{"too large", func(r *http.Request) { r.ContentLength = fileservice.MaxInputBytes + 1 }, 413, "preview_request_too_large"},
		{"get", func(r *http.Request) { r.Method = http.MethodGet }, 405, "method_not_allowed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := previewRequest(auth, cookie, emptyFileServiceFixture)
			test.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status {
				t.Fatalf("status %d, body %s", w.Code, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("unsafe headers")
			}
			if test.code != "" && !strings.Contains(w.Body.String(), `"error":"`+test.code+`"`) {
				t.Fatal(w.Body.String())
			}
			if w.Code == 405 && w.Header().Get("Allow") != "POST" {
				t.Fatal("incorrect Allow")
			}
			if w.Code == 200 {
				var p fileservice.Preview
				if json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Scope != "desired-policy-only" || p.Persisted || p.Applied || p.RuntimeValidated || p.ActivationAvailable {
					t.Fatal("activation boundary")
				}
			}
		})
	}
	for _, body := range []string{`{"shares":{"sensitive":"never-echo-this"},"nfs":{}}`, strings.Replace(emptyFileServiceFixture, `"volume_revision":1`, `"volume_revision":2`, 1)} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, previewRequest(auth, cookie, body))
		if w.Code != 422 || strings.Contains(w.Body.String(), "never-echo-this") {
			t.Fatal("policy errors leak or pass", w.Code)
		}
	}
	// Unknown-length/chunked requests must not bypass the byte ceiling.
	r := previewRequest(auth, cookie, strings.Repeat(" ", fileservice.MaxInputBytes+1))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal("unbounded chunked request", w.Code)
	}
	// Explicitly missing auth must fail closed.
	w = httptest.NewRecorder()
	newHandler(nil, nil, nil).ServeHTTP(w, previewRequest(auth, cookie, emptyFileServiceFixture))
	if w.Code != 401 {
		t.Fatal("preview available without auth")
	}
}

type heldPreviewBody struct {
	entered chan struct{}
	release chan struct{}
	once    sync.Once
	reader  io.Reader
}

type failingPreviewBody struct{ reads int }

func (b *failingPreviewBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("private body transport failure")
}
func (b *failingPreviewBody) Close() error { return nil }

func TestPreviewRejectsBeforeReadingAndReleasesFailedRead(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h := newHandler(nil, nil, auth)
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"session", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{"size", func(r *http.Request) { r.ContentLength = fileservice.MaxInputBytes + 1 }, 413},
		{"read failure", func(*http.Request) {}, 400},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := previewRequest(auth, cookie, emptyFileServiceFixture)
			body := &failingPreviewBody{}
			r.Body = body
			test.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || strings.Contains(w.Body.String(), "private") {
				t.Fatal("unexpected failure response", w.Code, w.Body.String())
			}
			if (test.status == 400) != (body.reads > 0) {
				t.Fatal("body read before authorization/header checks")
			}
			w = httptest.NewRecorder()
			h.ServeHTTP(w, previewRequest(auth, cookie, emptyFileServiceFixture))
			if w.Code != 200 {
				t.Fatal("failure retained preview slot", w.Code)
			}
		})
	}
}

func (b *heldPreviewBody) Read(p []byte) (int, error) {
	b.once.Do(func() { close(b.entered); <-b.release })
	return b.reader.Read(p)
}
func (b *heldPreviewBody) Close() error { return nil }

func TestPreviewConcurrencyGateDoesNotBlockHealth(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h := newHandler(nil, nil, auth)
	body := &heldPreviewBody{entered: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(emptyFileServiceFixture)}
	r := previewRequest(auth, cookie, emptyFileServiceFixture)
	r.Body = body
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w }()
	defer func() {
		select {
		case <-body.release:
		default:
			close(body.release)
		}
	}()
	select {
	case <-body.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("request did not enter")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, previewRequest(auth, cookie, emptyFileServiceFixture))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("missing preview backpressure")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, loopbackRequest(http.MethodGet, "/healthz", nil))
	if w.Code != 200 {
		t.Fatal("preview blocked health")
	}
	close(body.release)
	select {
	case result := <-done:
		if result.Code != 200 {
			t.Fatal(result.Body.String())
		}
	case <-time.After(3 * time.Second):
		t.Fatal("preview did not finish")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, previewRequest(auth, cookie, emptyFileServiceFixture))
	if w.Code != 200 {
		t.Fatal("preview slot not released")
	}
}
