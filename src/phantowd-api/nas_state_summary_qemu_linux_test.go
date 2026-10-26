//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func TestNASStateSummaryReadsOriginalOwnerThroughRouter(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	r := shareReadRequest(cookie)
	r.URL.Path = "/api/v1/nas-services/summary"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	c := qemuPersistentNASPolicy(1)
	luns := 0
	for _, target := range c.ISCSI.Targets {
		luns += len(target.LUNs)
	}
	want := map[string]any{"schema_version": float64(1), "scope": "stored-desired-nas-policy-summary-only", "revision": float64(1),
		"volumes": float64(len(c.FileServices.Shares.Volumes)), "users": float64(len(c.FileServices.Shares.Users)),
		"smb_shares": float64(len(c.FileServices.Shares.Shares)), "nfs_exports": float64(len(c.FileServices.NFS.Exports)),
		"iscsi_targets": float64(len(c.ISCSI.Targets)), "iscsi_backings": float64(len(c.ISCSI.Backings)), "iscsi_luns": float64(luns),
		"applied": false, "activation_available": false}
	var got map[string]any
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &got) != nil || !reflect.DeepEqual(got, want) || w.Body.Len() > 1024 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("coherent compact NAS summary unavailable", w.Code, w.Body.String())
	}
	current, err := owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, c) {
		t.Fatal("summary changed original policy")
	}
}

func TestNASStateSummaryRefusesInputAndUnavailableAuthority(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, newNASStateHandler(auth, owner))
	for _, tc := range []struct {
		method, suffix string
		status         int
	}{
		{"GET", "", 200}, {"PUT", "", 405}, {"POST", "", 405}, {"DELETE", "", 405},
		{"GET", "/extra", 404},
	} {
		r := shareReadRequest(cookie)
		r.Method, r.URL.Path = tc.method, nasSummaryPath+tc.suffix
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || tc.status == 405 && w.Header().Get("Allow") != "GET" {
			t.Fatal(w.Code, tc)
		}
	}
	for _, tc := range []struct {
		change func(*http.Request)
		status int
	}{
		{func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") }, 403},
		{func(r *http.Request) { r.URL.RawQuery = "apply=true" }, 400},
		{func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader("x")); r.ContentLength = 1 }, 400},
	} {
		r := shareReadRequest(cookie)
		r.URL.Path = nasSummaryPath
		tc.change(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "revision") {
			t.Fatal("refused summary returned data", w.Code)
		}
	}
	for _, state := range []nasStateAuthority{nil, summaryInvalidState{}, owner} {
		if state == owner {
			if err := owner.Close(); err != nil {
				t.Fatal(err)
			}
		}
		r := shareReadRequest(cookie)
		r.URL.Path = nasSummaryPath
		w := httptest.NewRecorder()
		newNASStateHandler(auth, state)(w, r)
		if w.Code != 503 || strings.Contains(w.Body.String(), "revision") {
			t.Fatal("unavailable summary returned data", w.Code)
		}
	}
}

type summaryInvalidState struct{}

func (summaryInvalidState) Snapshot(context.Context) (naspolicy.Config, error) {
	return naspolicy.Config{}, nil
}
func (summaryInvalidState) Commit(context.Context, uint64, naspolicy.Config) error {
	panic("summary must never commit")
}
