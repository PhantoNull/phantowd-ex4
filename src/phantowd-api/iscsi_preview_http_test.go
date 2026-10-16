// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const emptyNASPreviewFixture = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":1,"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":1,"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,"volumes":[],"users":[],"shares":[]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,"exports":[]}},"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":1,"volume_revision":1,"backings":[],"targets":[]}}`

func iscsiRequest(auth *authController, cookie *http.Cookie, body string) *http.Request {
	r := previewRequest(auth, cookie, body)
	r.URL.Path = iscsiPreviewPath
	return r
}

func nonemptyNASPreviewFixture(t *testing.T) string {
	t.Helper()
	c, err := naspolicy.Decode(strings.NewReader(emptyNASPreviewFixture))
	if err != nil {
		t.Fatal(err)
	}
	c.Revision, c.FileServices.Revision, c.FileServices.Shares.Revision = math.MaxUint64, math.MaxUint64, math.MaxUint64
	c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision, c.ISCSI.Revision, c.ISCSI.VolumeRevision = math.MaxUint64, math.MaxUint64, math.MaxUint64, math.MaxUint64
	c.FileServices.Shares.Volumes = []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-3333-4444-555555555555"}}
	c.ISCSI.Backings = []iscsipolicy.Backing{{ID: "backing", VolumeID: "bulk", RelativePath: "luns/not-opened.img", CapacityBytes: math.MaxInt64 - 4095, BlockSize: 4096, Allocation: "sparse"}}
	c.ISCSI.Targets = []iscsipolicy.Target{{ID: "target", Name: "iqn.2001-04.com.example:target", State: "enabled", LUNs: []iscsipolicy.LUN{{ID: "lun", Number: 0, BackingID: "backing", Access: "rw"}}, Initiators: []iscsipolicy.Initiator{{Name: "iqn.2001-04.com.example:peer", Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "private-user", InitiatorSecretRef: "private-ref"}, Grants: []iscsipolicy.Grant{{LUNID: "lun", Access: "ro"}}}}}}
	if c.Validate() != nil {
		t.Fatal("nonempty whole-policy fixture invalid")
	}
	data, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func TestISCSIPreviewHTTPExactNonemptyProjection(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h := newHandler(nil, nil, auth)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, iscsiRequest(auth, cookie, nonemptyNASPreviewFixture(t)))
	var p iscsipreview.Preview
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Revision != "18446744073709551615" || len(p.Backings) != 1 || p.Backings[0].CapacityBytes != "9223372036854771712" || len(p.Targets) != 1 || p.Targets[0].LUNs[0].Number != 0 || p.Targets[0].Initiators[0].Grants[0].Access != "ro" || p.Targets[0].DesiredState != "enabled" || p.ActivationAvailable || p.RuntimeValidated {
		t.Fatal("nonempty preview lost precision, relationships or desired/runtime distinction", w.Code)
	}
	for _, private := range []string{"private-user", "private-ref", "11111111-2222-3333-4444-555555555555", "secret_ref", "initiator_user"} {
		if strings.Contains(w.Body.String(), private) {
			t.Fatal("preview exposed private credential or raw filesystem field")
		}
	}
}

func TestISCSIPreviewHTTPBoundary(t *testing.T) {
	auth, cookie := newTestAuth(t)
	h := newHandler(nil, nil, auth)
	for _, test := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"valid", func(*http.Request) {}, 200},
		{"utf8", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=UTF-8") }, 200},
		{"no session", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"origin", func(r *http.Request) { r.Header.Del("Origin") }, 403},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://foreign.invalid") }, 403},
		{"host", func(r *http.Request) { r.Host = "foreign.invalid" }, 403},
		{"csrf", func(r *http.Request) { r.Header.Del("X-PhantoWD-CSRF") }, 403},
		{"wrong csrf", func(r *http.Request) { r.Header.Set("X-PhantoWD-CSRF", "wrong") }, 403},
		{"duplicate csrf", func(r *http.Request) { r.Header.Add("X-PhantoWD-CSRF", r.Header.Get("X-PhantoWD-CSRF")) }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "save=true" }, 400},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }, 400},
		{"empty encoding", func(r *http.Request) { r.Header.Set("Content-Encoding", "") }, 400},
		{"type", func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }, 400},
		{"duplicate type", func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }, 400},
		{"charset", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }, 400},
		{"parameter", func(r *http.Request) { r.Header.Set("Content-Type", "application/json; boundary=x") }, 400},
		{"declared size", func(r *http.Request) { r.ContentLength = naspolicy.MaxInputBytes + 1 }, 413},
		{"get", func(r *http.Request) { r.Method = "GET" }, 405},
		{"put", func(r *http.Request) { r.Method = "PUT" }, 405},
		{"canceled", func(r *http.Request) {
			ctx, cancel := context.WithCancel(r.Context())
			cancel()
			*r = *r.WithContext(ctx)
		}, 408},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := iscsiRequest(auth, cookie, emptyNASPreviewFixture)
			test.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != test.status || w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatalf("boundary status=%d want=%d", w.Code, test.status)
			}
			if w.Code == 200 {
				var p iscsipreview.Preview
				if json.Unmarshal(w.Body.Bytes(), &p) != nil || p.Revision != "1" || p.Format != iscsipreview.Format || p.Targets == nil || p.Backings == nil || p.ActivationAvailable || p.StorageValidated || p.CredentialsValidated || p.RuntimeValidated || w.Body.Len() > iscsipreview.MaxOutputBytes {
					t.Fatal("empty desired preview acquired authority or lost its bounded shape")
				}
			}
		})
	}
	for _, body := range []string{`{}`, `{"PRIVATE":true}`, strings.Replace(emptyNASPreviewFixture, `"revision":1`, `"revision":2`, 1), strings.Replace(emptyNASPreviewFixture, `"targets":[]`, `"targets":[],"targets":[]`, 1), emptyNASPreviewFixture + `{}`} {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, iscsiRequest(auth, cookie, body))
		if w.Code != 422 || strings.Contains(w.Body.String(), "PRIVATE") {
			t.Fatal("invalid whole revision accepted/leaked")
		}
	}
	r := iscsiRequest(auth, cookie, strings.Repeat(" ", naspolicy.MaxInputBytes+1))
	r.ContentLength = -1
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 413 {
		t.Fatal("chunked request bypassed limit")
	}
	w = httptest.NewRecorder()
	newHandler(nil, nil, nil).ServeHTTP(w, iscsiRequest(auth, cookie, emptyNASPreviewFixture))
	if w.Code != 401 {
		t.Fatal("missing authentication accepted")
	}
}

func TestISCSIPreviewGateRevocationAndNoStore(t *testing.T) {
	auth, cookie := newTestAuth(t)
	calls := 0
	backend := &serviceStateBackend{load: func() (*fileservice.Config, error) { calls++; return nil, nil }, commit: func(uint64, fileservice.Config) error { calls++; return nil }}
	h := newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend)
	held := &heldPreviewBody{entered: make(chan struct{}), release: make(chan struct{}), reader: strings.NewReader(emptyNASPreviewFixture)}
	r := iscsiRequest(auth, cookie, emptyNASPreviewFixture)
	r.Body = held
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, r); done <- w }()
	select {
	case <-held.entered:
	case <-time.After(3 * time.Second):
		close(held.release)
		t.Fatal("preview did not enter bounded body test")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, iscsiRequest(auth, cookie, emptyNASPreviewFixture))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		close(held.release)
		<-done
		t.Fatal("preview gate queued a second body")
	}
	broken := &failingPreviewBody{}
	r2 := iscsiRequest(auth, cookie, emptyNASPreviewFixture)
	r2.Header.Del("Cookie")
	r2.Body = broken
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r2)
	if w.Code != 401 || broken.reads != 0 {
		close(held.release)
		<-done
		t.Fatal("body read before authorization")
	}
	auth.sessions.revoke(cookie.Value)
	close(held.release)
	if result := <-done; result.Code != 401 || calls != 0 {
		t.Fatal("revoked request published or touched configured store")
	}
	// New fixture: a read failure releases its own slot, never emits body errors.
	auth, cookie = newTestAuth(t)
	h = newHandler(nil, nil, auth)
	r = iscsiRequest(auth, cookie, emptyNASPreviewFixture)
	r.Body = broken
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 400 || strings.Contains(w.Body.String(), "private") {
		t.Fatal("body failure leaked")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, iscsiRequest(auth, cookie, emptyNASPreviewFixture))
	if w.Code != 200 {
		t.Fatal("failed body retained preview slot")
	}
	// Inclusive total bound remains accepted without waiving child limits.
	text := emptyNASPreviewFixture + strings.Repeat(" ", naspolicy.MaxInputBytes-len(emptyNASPreviewFixture))
	w = httptest.NewRecorder()
	h.ServeHTTP(w, iscsiRequest(auth, cookie, text))
	if w.Code != 200 {
		t.Fatal("inclusive envelope refused")
	}
}
