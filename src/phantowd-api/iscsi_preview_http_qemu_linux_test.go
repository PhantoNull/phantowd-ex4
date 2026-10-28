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
	"sync"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func iscsiPreviewRequest(auth *authController, cookie *http.Cookie, body string) *http.Request {
	r := previewRequest(auth, cookie, body)
	r.URL.Path = "/api/v1/iscsi/preview"
	return r
}
func iscsiPreviewInput(t *testing.T) string {
	t.Helper()
	c := qemuPersistentNASPolicy(^uint64(0))
	c.ISCSI.Backings[0].CapacityBytes = (1 << 63) - 4096
	c.FileServices.Shares.Shares[0].RelativePath, c.FileServices.NFS.Exports[0].RelativePath = ".", "luns"
	c.ISCSI.Targets[0].State, c.ISCSI.Targets[0].Initiators[0].Grants[0].Access = "enabled", "ro"
	a := &c.ISCSI.Targets[0].Initiators[0].Authentication
	a.Mode, a.InitiatorUser, a.InitiatorSecretRef, a.TargetUser, a.TargetSecretRef = "mutual-chap", "private-in-user", "private-in-ref", "private-out-user", "private-out-ref"
	if c.Validate() != nil {
		t.Fatal("invalid synthetic coherent input")
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
func TestISCSIPreviewHTTPProjection(t *testing.T) {
	auth, cookie := newTestAuth(t)
	w := httptest.NewRecorder()
	backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { panic("unexpected state read") }, commit: func(uint64, fileservice.Config) error { panic("unexpected state write") }}
	newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend).ServeHTTP(w, iscsiPreviewRequest(auth, cookie, iscsiPreviewInput(t)))
	if w.Code != 200 {
		t.Fatal("iSCSI preview unavailable", w.Code, w.Body.String())
	}
	var p map[string]any
	if json.Unmarshal(w.Body.Bytes(), &p) != nil || w.Body.Len() > 256<<10 {
		t.Fatal("invalid bounded preview")
	}
	if limitations, ok := p["limitations"].([]any); !ok || len(limitations) == 0 {
		t.Fatal("limitations missing")
	}
	delete(p, "limitations")
	const want = `{"format":"phantowd-desired-iscsi-preview","schema_version":2,"scope":"desired-policy-only","revision":"18446744073709551615","storage_validated":false,"credentials_validated":false,"runtime_validated":false,"activation_available":false,"smb_definitions":1,"nfs_definitions":1,
 "backings":[{"id":"fixture-backing","volume_id":"fixture-volume","relative_path":"luns/new.img","capacity_bytes":"9223372036854771712","block_size":512,"allocation":"preallocated","smb_path_overlap_count":1,"nfs_path_overlap_count":1}],
 "targets":[{"id":"fixture-target","name":"iqn.2001-04.com.example:fixture-target","desired_state":"enabled","luns":[{"id":"fixture-lun","number":0,"backing_id":"fixture-backing","access":"rw"}],"initiators":[{"name":"iqn.2001-04.com.example:fixture-peer","desired_authentication":"mutual-chap","grants":[{"lun_id":"fixture-lun","access":"ro"}]}]}]}`
	var expected map[string]any
	if json.Unmarshal([]byte(want), &expected) != nil || !reflect.DeepEqual(p, expected) {
		t.Fatal("public desired relationships, decimal precision or shape changed")
	}
	for _, private := range []string{"private-in-user", "private-in-ref", "private-out-user", "private-out-ref", "secret_ref", "12345678-1234-1234-1234-123456789abc", "192.0.2.10/32"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("private field leaked")
		}
	}
}

func TestISCSIPreviewHTTPRefusals(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h, input := newHandler(nil, nil, auth), iscsiPreviewInput(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		change func(*http.Request)
		status int
	}{
		{func(r *http.Request) { r.Method = "GET" }, 405},
		{func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{func(r *http.Request) { r.Host = "foreign.invalid" }, 403},
		{func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{func(r *http.Request) { r.ContentLength = naspolicy.MaxInputBytes + 1 }, 413},
		{func(r *http.Request) {
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat(" ", naspolicy.MaxInputBytes+1)))
		}, 413},
		{func(r *http.Request) { r.Body = io.NopCloser(strings.NewReader(input + "{}")) }, 422},
		{func(r *http.Request) { *r = *r.WithContext(ctx) }, 408},
	} {
		r := iscsiPreviewRequest(auth, cookie, input)
		r.ContentLength = -1
		test.change(r)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != test.status || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
			t.Fatal("preview boundary failed", w.Code, test.status)
		}
	}
}
func TestISCSIPreviewHTTPGateAndRevocation(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h, input := newHandler(nil, nil, auth), iscsiPreviewInput(t)
	held := &heldPreviewBody{entered: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(input)}
	var once sync.Once
	release := func() { once.Do(func() { close(held.release) }) }
	defer release()
	r := iscsiPreviewRequest(auth, cookie, input)
	r.Body = held
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w.Code }()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		t.Fatal("body not reached")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, iscsiPreviewRequest(auth, cookie, input))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("preview queued a second body")
	}
	auth.sessions.revoke(cookie.Value)
	release()
	select {
	case code := <-done:
		if code != 401 {
			t.Fatal("revoked session returned a preview", code)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("preview did not settle")
	}
}
