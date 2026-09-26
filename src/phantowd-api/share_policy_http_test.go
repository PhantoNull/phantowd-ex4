// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func shareReadRequest(cookie *http.Cookie) *http.Request {
	r := loopbackRequest(http.MethodGet, sharePolicyPath, nil)
	r.AddCookie(cookie)
	return r
}

func testStoredPolicy() *shareconfig.Config {
	return &shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 4,
		Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
}

func TestSharePolicyReadHTTP(t *testing.T) {
	auth, cookie := newTestAuth(t)
	for _, spec := range []struct {
		name   string
		change func(*http.Request)
		status int
	}{
		{"valid", func(*http.Request) {}, 200},
		{"origin", func(r *http.Request) { r.Header.Set("Origin", defaultPublicOrigin) }, 200},
		{"foreign origin", func(r *http.Request) { r.Header.Set("Origin", "https://evil.invalid") }, 403},
		{"null origin", func(r *http.Request) { r.Header.Set("Origin", "null") }, 403},
		{"duplicate origin", func(r *http.Request) { r.Header["Origin"] = []string{defaultPublicOrigin, defaultPublicOrigin} }, 403},
		{"host", func(r *http.Request) { r.Host = "evil.invalid" }, 403},
		{"query", func(r *http.Request) { r.URL.RawQuery = "path=/private" }, 400},
		{"empty query", func(r *http.Request) { r.URL.ForceQuery = true }, 400},
		{"body", func(r *http.Request) { r.ContentLength = 1 }, 400},
		{"chunked", func(r *http.Request) { r.ContentLength = -1; r.TransferEncoding = []string{"chunked"} }, 400},
		{"unauthenticated", func(r *http.Request) { r.Header.Del("Cookie") }, 401},
		{"post", func(r *http.Request) { r.Method = http.MethodPost }, 405},
		{"head", func(r *http.Request) { r.Method = http.MethodHead }, 405},
		{"put", func(r *http.Request) { r.Method = http.MethodPut }, 405},
	} {
		t.Run(spec.name, func(t *testing.T) {
			calls := 0
			h := newHandlerWithSharePolicy(nil, nil, nil, nil, auth, func() (*shareconfig.Config, error) { calls++; return testStoredPolicy(), nil })
			r := shareReadRequest(cookie)
			spec.change(r)
			w := httptest.NewRecorder()
			h.ServeHTTP(w, r)
			if w.Code != spec.status || (calls == 1) != (spec.status == 200) {
				t.Fatal(w.Code, calls, w.Body.String())
			}
			if w.Header().Get("Cache-Control") != "no-store" || w.Header().Get("X-Content-Type-Options") != "nosniff" || w.Header().Get("Access-Control-Allow-Origin") != "" {
				t.Fatal("unsafe response headers")
			}
			if w.Code == 405 && w.Header().Get("Allow") != "GET" {
				t.Fatal("mutation accepted")
			}
			if w.Code == 200 {
				var response sharePolicyResponse
				if json.Unmarshal(w.Body.Bytes(), &response) != nil || !response.Initialized || response.Configuration.Revision != 4 || response.RuntimeValidated || response.ActivationAvailable || response.Scope != "stored-desired-share-policy-only" {
					t.Fatal("policy or authority boundary", w.Body.String())
				}
			}
		})
	}
	for _, spec := range []struct {
		name   string
		load   sharePolicyLoader
		status int
	}{
		{"disabled", nil, 503},
		{"uninitialized", func() (*shareconfig.Config, error) { return nil, nil }, 200},
		{"private error", func() (*shareconfig.Config, error) {
			return testStoredPolicy(), errors.New("private path and metadata")
		}, 503},
		{"invalid", func() (*shareconfig.Config, error) { return &shareconfig.Config{}, nil }, 503},
		{"oversized valid model", func() (*shareconfig.Config, error) {
			p := testStoredPolicy()
			p.Volumes = []shareconfig.Volume{{ID: "volume", FilesystemUUID: "00112233-4455-6677-8899-aabbccddeeff"}}
			var grants []shareconfig.Grant
			for i := 0; i < shareconfig.MaxUsers; i++ {
				id := fmt.Sprintf("user%d", i)
				p.Users = append(p.Users, shareconfig.User{ID: id, Name: id})
				grants = append(grants, shareconfig.Grant{UserID: id, Access: "ro"})
			}
			for i := 0; i < shareconfig.MaxShares; i++ {
				id := fmt.Sprintf("share%d", i)
				p.Shares = append(p.Shares, shareconfig.Share{ID: id, Name: id, VolumeID: "volume", RelativePath: id, Grants: grants})
			}
			if p.Validate() != nil {
				t.Fatal("oversize test failed before encoded-size boundary")
			}
			return p, nil
		}, 503},
	} {
		t.Run(spec.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			newHandlerWithSharePolicy(nil, nil, nil, nil, auth, spec.load).ServeHTTP(w, shareReadRequest(cookie))
			if w.Code != spec.status || strings.Contains(w.Body.String(), "private") {
				t.Fatal(w.Code, w.Body.String())
			}
			if spec.name == "uninitialized" && (!strings.Contains(w.Body.String(), `"initialized":false`) || !strings.Contains(w.Body.String(), `"configuration":null`)) {
				t.Fatal("absence became empty policy")
			}
		})
	}
	w := httptest.NewRecorder()
	newHandlerWithSharePolicy(nil, nil, nil, nil, nil, func() (*shareconfig.Config, error) { t.Fatal("loaded without auth"); return nil, nil }).ServeHTTP(w, shareReadRequest(cookie))
	if w.Code != 401 {
		t.Fatal(w.Code)
	}
}

func TestSharePolicyReadBackpressure(t *testing.T) {
	auth, cookie := newTestAuth(t)
	entered, release := make(chan struct{}), make(chan struct{})
	var calls atomic.Int32
	h := newHandlerWithSharePolicy(nil, nil, nil, nil, auth, func() (*shareconfig.Config, error) {
		if calls.Add(1) == 1 {
			close(entered)
			<-release
			return nil, errors.New("read failed")
		}
		return nil, nil
	})
	done := make(chan int, 1)
	go func() { w := httptest.NewRecorder(); h.ServeHTTP(w, shareReadRequest(cookie)); done <- w.Code }()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		t.Fatal("load not entered")
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, shareReadRequest(cookie))
	if w.Code != 503 || w.Header().Get("Retry-After") != "1" {
		t.Fatal("missing single-reader gate")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, loopbackRequest(http.MethodGet, "/healthz", nil))
	if w.Code != 200 {
		t.Fatal("storage read blocked health")
	}
	close(release)
	select {
	case status := <-done:
		if status != 503 {
			t.Fatal(status)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("read did not finish")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, shareReadRequest(cookie))
	if w.Code != 200 || calls.Load() != 2 {
		t.Fatal("failed read retained slot")
	}
}
