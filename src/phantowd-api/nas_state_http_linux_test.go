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
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

func TestNASStateRefusalsLeaveTheFullDocumentUnchanged(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newNASStateHandler(auth, owner)
	data, _ := json.Marshal(qemuPersistentNASPolicy(2))
	for _, tc := range []struct {
		change func(*http.Request)
		status int
	}{
		{func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{func(r *http.Request) { r.Host = "other.invalid" }, 403},
		{func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{func(r *http.Request) { r.Header.Add("X-PhantoWD-CSRF", "duplicate") }, 403},
		{func(r *http.Request) { r.URL.RawQuery = "apply=true" }, 400},
		{func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{func(r *http.Request) { r.ContentLength = naspolicy.MaxInputBytes + 1 }, 413},
		{func(r *http.Request) {
			r.ContentLength = -1
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", naspolicy.MaxInputBytes+1)))
		}, 413},
		{func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(`{"private-value":true}`)) }, 422},
		{func(r *http.Request) { r.Method = http.MethodGet }, 400},
		{func(r *http.Request) { r.Method = http.MethodDelete }, 405},
	} {
		r := serviceWriteRequest(auth, cookie, serviceConfigFixture(2))
		r.URL.Path, r.Body, r.ContentLength = nasStatePath, io.NopCloser(strings.NewReader(string(data))), int64(len(data))
		tc.change(r)
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != tc.status || strings.Contains(w.Body.String(), "private-value") {
			t.Fatal(w.Code, tc.status, w.Body.String())
		}
	}
	current, err := owner.Snapshot(context.Background())
	if err != nil || !reflect.DeepEqual(current, qemuPersistentNASPolicy(1)) {
		t.Fatal("refused input changed the original policy")
	}
}

func nasStateTestOwner(t *testing.T) *naspolicystore.Owner {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	seed, err := naspolicystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := seed.Commit(0, qemuPersistentNASPolicy(1)); err != nil {
		t.Fatal(err)
	}
	if err := seed.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err := naspolicystore.OpenOwner(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := owner.Close(); err != nil {
			t.Error(err)
		}
	})
	return owner
}

func TestNASStateUsesTheOriginalOwnerAndItsClaims(t *testing.T) {
	owner := nasStateTestOwner(t)
	auth, cookie := newTestAuth(t)
	h := newNASStateHandler(auth, owner)
	read := func(revision uint64) {
		t.Helper()
		r := shareReadRequest(cookie)
		r.URL.Path = nasStatePath
		w := httptest.NewRecorder()
		h(w, r)
		var reply nasStateResponse
		if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &reply) != nil || reply.Configuration == nil ||
			!reflect.DeepEqual(*reply.Configuration, qemuPersistentNASPolicy(revision)) || reply.Saved || reply.Applied || reply.ActivationAvailable {
			t.Fatal("original full NAS policy was not read", w.Code, w.Body.String())
		}
	}
	write := func(want int) {
		t.Helper()
		data, _ := json.Marshal(qemuPersistentNASPolicy(2))
		r := serviceWriteRequest(auth, cookie, serviceConfigFixture(2))
		r.URL.Path, r.Body, r.ContentLength = nasStatePath, io.NopCloser(strings.NewReader(string(data))), int64(len(data))
		w := httptest.NewRecorder()
		h(w, r)
		if w.Code != want || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	read(1)
	claim, err := owner.Acquire(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	write(503)
	read(1)
	if err := claim.Release(); err != nil {
		t.Fatal(err)
	}
	write(200)
	read(2)
	write(409)
	read(2)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	r := shareReadRequest(cookie)
	r.URL.Path = nasStatePath
	w := httptest.NewRecorder()
	h(w, r)
	if w.Code != 503 || strings.Contains(w.Body.String(), "configuration\"") {
		t.Fatal("closed Owner returned a configuration")
	}
}
