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
)

func restoreRequest(t *testing.T, auth *authController, cookie *http.Cookie, revision string) *http.Request {
	t.Helper()
	data, err := fileservice.EncodeBackup(serviceConfigFixture(71))
	if err != nil {
		t.Fatal(err)
	}
	r := previewRequest(auth, cookie, string(data))
	r.URL.Path = serviceRestorePreviewPath
	r.Header.Set(serviceExpectedRevisionHeader, revision)
	return r
}

func TestServiceBackupRestoreExplicitSave(t *testing.T) {
	auth, cookie := newTestAuth(t)
	current := serviceConfigFixture(7)
	commits := 0
	backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { return &current, nil }, commit: func(expected uint64, c fileservice.Config) error {
		if expected != current.Revision {
			return errServiceStateConflict
		}
		commits++
		current = c
		return nil
	}}
	h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	w := httptest.NewRecorder()
	r := shareReadRequest(cookie)
	r.URL.Path = serviceBackupPath
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Header().Get("Content-Disposition") != `attachment; filename="phantowd-file-services.json"` || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(w.Code, w.Header())
	}
	if _, err := fileservice.RestoreCandidate(w.Body.Bytes(), 7); err != nil {
		t.Fatal("download cannot be imported", err)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, restoreRequest(t, auth, cookie, "7"))
	var reply struct {
		Configuration fileservice.Config  `json:"configuration"`
		Preview       fileservice.Preview `json:"preview"`
		Expected      uint64              `json:"expected_revision"`
		Saved         bool                `json:"saved"`
		Applied       bool                `json:"applied"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Configuration.Revision != 8 || reply.Expected != 7 || reply.Saved || reply.Applied || reply.Preview.Applied || reply.Preview.Persisted || reply.Preview.ActivationAvailable || commits != 0 || current.Revision != 7 {
		t.Fatal(w.Code, w.Body.String(), commits)
	}
	// A preview is not a reservation: a different writer may change the baseline.
	current = serviceConfigFixture(8)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, serviceWriteRequest(auth, cookie, reply.Configuration))
	if w.Code != 409 || commits != 0 {
		t.Fatal("stale restore committed", w.Code)
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, restoreRequest(t, auth, cookie, "8"))
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Configuration.Revision != 9 {
		t.Fatal(w.Code, w.Body.String())
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, serviceWriteRequest(auth, cookie, reply.Configuration))
	if w.Code != 200 || commits != 1 || current.Revision != 9 {
		t.Fatal("explicit save failed", w.Code, commits)
	}
}

func TestServiceRestoreHTTPBoundary(t *testing.T) {
	auth, cookie := newTestAuth(t)
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
		status int
		loads  int
	}{
		{"valid", func(*http.Request) {}, 200, 1},
		{"unauthenticated", func(r *http.Request) { r.Header.Del("Cookie") }, 401, 0},
		{"origin absent", func(r *http.Request) { r.Header.Del("Origin") }, 403, 0},
		{"foreign host", func(r *http.Request) { r.Host = "foreign.invalid" }, 403, 0},
		{"origin twice", func(r *http.Request) { r.Header.Add("Origin", defaultPublicOrigin) }, 403, 0},
		{"CSRF absent", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403, 0},
		{"CSRF twice", func(r *http.Request) { r.Header.Add("X-PhantoWD-CSRF", r.Header.Get("X-PhantoWD-CSRF")) }, 403, 0},
		{"revision absent", func(r *http.Request) { r.Header.Del(serviceExpectedRevisionHeader) }, 400, 0},
		{"revision twice", func(r *http.Request) { r.Header.Add(serviceExpectedRevisionHeader, "7") }, 400, 0},
		{"revision padded", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "07") }, 400, 0},
		{"revision signed", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "+7") }, 400, 0},
		{"revision overflow", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "18446744073709551616") }, 400, 0},
		{"revision exhausted", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "18446744073709551615") }, 422, 0},
		{"revision stale", func(r *http.Request) { r.Header.Set(serviceExpectedRevisionHeader, "6") }, 409, 1},
		{"query", func(r *http.Request) { r.URL.RawQuery = "apply=true" }, 400, 0},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, 400, 0},
		{"compression", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400, 0},
		{"wrong type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400, 0},
		{"charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }, 400, 0},
		{"oversize known", func(r *http.Request) { r.ContentLength = fileservice.MaxBackupBytes + 1 }, 413, 0},
		{"oversize chunked", func(r *http.Request) {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", fileservice.MaxBackupBytes+1)))
		}, 413, 0},
		{"unknown secret", func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"password":"private-secret"}`)) }, 422, 0},
		{"cancelled", func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}, 400, 0},
		{"GET refused", func(r *http.Request) { r.Method = http.MethodGet }, 405, 0},
		{"PUT refused", func(r *http.Request) { r.Method = http.MethodPut }, 405, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loads := 0
			backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { loads++; c := serviceConfigFixture(7); return &c, nil }, commit: func(uint64, fileservice.Config) error { t.Fatal("preview committed"); return nil }}
			h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
			r := restoreRequest(t, auth, cookie, "7")
			tc.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || loads != tc.loads || strings.Contains(w.Body.String(), "private-secret") {
				t.Fatal(w.Code, loads, w.Body.String())
			}
		})
	}
}

func TestServiceBackupReadFailureAndSessionRecheck(t *testing.T) {
	for _, mode := range []string{"missing-backend", "uninitialized", "corrupt", "uncertain", "revoked", "cancelled", "valid"} {
		t.Run(mode, func(t *testing.T) {
			auth, cookie := newTestAuth(t)
			r := shareReadRequest(cookie)
			r.URL.Path = serviceBackupPath
			ctx, cancel := context.WithCancel(r.Context())
			defer cancel()
			r = r.WithContext(ctx)
			backend := &serviceStateBackend{load: func() (*fileservice.Config, error) {
				switch mode {
				case "uninitialized":
					return nil, nil
				case "corrupt":
					return &fileservice.Config{}, nil
				case "uncertain":
					return nil, errServiceStateUncertain
				case "revoked":
					auth.sessions.revoke(cookie.Value)
				case "cancelled":
					cancel()
				}
				c := serviceConfigFixture(7)
				return &c, nil
			}, commit: func(uint64, fileservice.Config) error { t.Fatal("export committed"); return nil }}
			if mode == "missing-backend" {
				backend = nil
			}
			h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			want := map[string]int{"missing-backend": 503, "uninitialized": 409, "corrupt": 503, "uncertain": 503, "revoked": 401, "cancelled": 400, "valid": 200}[mode]
			if w.Code != want || (w.Header().Get("Content-Disposition") != "") != (mode == "valid") {
				t.Fatal(w.Code, w.Body.String())
			}
		})
	}
}

func TestServiceBackupSharesWriteAdmissionGate(t *testing.T) {
	auth, cookie := newTestAuth(t)
	entered, release := make(chan struct{}), make(chan struct{})
	backend := &serviceStateBackend{load: func() (*fileservice.Config, error) {
		close(entered)
		<-release
		c := serviceConfigFixture(7)
		return &c, nil
	}, commit: func(uint64, fileservice.Config) error {
		t.Fatal("concurrent write admitted")
		return errors.New("unreachable")
	}}
	h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		r := shareReadRequest(cookie)
		r.URL.Path = serviceBackupPath
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		done <- w
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("backup did not enter store")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, serviceWriteRequest(auth, cookie, serviceConfigFixture(8)))
	close(release)
	if w.Code != 503 || !strings.Contains(w.Body.String(), "service_configuration_busy") {
		t.Fatal(w.Code, w.Body.String())
	}
	select {
	case result := <-done:
		if result.Code != 200 {
			t.Fatal(result.Code)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("backup did not drain")
	}
}

func TestServiceBackupReadHTTPBoundary(t *testing.T) {
	auth, cookie := newTestAuth(t)
	for _, tc := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"valid", func(*http.Request) {}, 200},
		{"no session", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"foreign host", func(r *http.Request) { r.Host = "foreign.invalid" }, 403},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "http://foreign.invalid") }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "all=true" }, 400},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"body", func(r *http.Request) { r.ContentLength = 1; r.Body = io.NopCloser(strings.NewReader("x")) }, 400},
		{"chunked", func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, 400},
		{"head", func(r *http.Request) { r.Method = http.MethodHead }, 405},
		{"put", func(r *http.Request) { r.Method = http.MethodPut }, 405},
	} {
		t.Run(tc.name, func(t *testing.T) {
			loads := 0
			backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { loads++; c := serviceConfigFixture(7); return &c, nil }, commit: func(uint64, fileservice.Config) error { t.Fatal("export committed"); return nil }}
			h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
			r := shareReadRequest(cookie)
			r.URL.Path = serviceBackupPath
			tc.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != tc.status || (loads == 1) != (tc.status == 200) {
				t.Fatal(w.Code, loads, w.Body.String())
			}
		})
	}
}
