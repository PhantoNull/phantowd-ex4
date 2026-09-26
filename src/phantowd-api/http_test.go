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
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"
)

const testAdminPassword = "test-only correct horse battery staple"

func newTestAuth(t *testing.T) (*authController, *http.Cookie) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	accounts, err := openAccountStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := accounts.setup(context.Background(), "test-admin", testAdminPassword); err != nil {
		t.Fatal(err)
	}
	auth := newAuthController(accounts, defaultPublicOrigin)
	token, _, err := auth.sessions.create(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return auth, &http.Cookie{Name: sessionCookieName, Value: token, Path: "/"}
}

func loopbackRequest(method, target string, body io.Reader) *http.Request {
	request := httptest.NewRequest(method, target, body)
	request.Host = "127.0.0.1:8080"
	return request
}

func TestHTTPContract(t *testing.T) {
	for _, test := range []struct {
		name, method, path, body string
		status                   int
		collect                  bool
	}{
		{"health", "GET", "/healthz", "", 200, false},
		{"system", "GET", "/api/v1/system", "", 200, true},
		{"post", "POST", "/api/v1/system", "", 405, false},
		{"put", "PUT", "/api/v1/system", "", 405, false},
		{"delete", "DELETE", "/api/v1/system", "", 405, false},
		{"head", "HEAD", "/healthz", "", 405, false},
		{"options", "OPTIONS", "/healthz", "", 405, false},
		{"query", "GET", "/api/v1/system?path=/dev/mtd3", "", 400, false},
		{"empty query", "GET", "/api/v1/system?", "", 400, false},
		{"body", "GET", "/api/v1/system", "unexpected", 400, false},
		{"unknown", "GET", "/api/v1/reboot", "", 404, false},
		{"traversal", "GET", "/api/v1/system/../../etc/shadow", "", 404, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			auth, cookie := newTestAuth(t)
			called := false
			handler := newHandler(func() (systemSnapshot, error) {
				called = true
				return collectSystem(fixtureProc(), time.Now())
			}, nil, auth)
			request := loopbackRequest(test.method, test.path, strings.NewReader(test.body))
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status || called != test.collect {
				t.Fatalf("status=%d called=%t", response.Code, called)
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("Content-Type") != "application/json" {
				t.Fatal("missing safe response headers")
			}
			if test.status == 405 && response.Header().Get("Allow") != "GET" {
				t.Fatal("incorrect allowed methods")
			}
			if !json.Valid(response.Body.Bytes()) {
				t.Fatal("invalid JSON response")
			}
		})
	}
}

func TestDiagnosticsFailureDoesNotLeak(t *testing.T) {
	auth, cookie := newTestAuth(t)
	handler := newHandler(func() (systemSnapshot, error) {
		return systemSnapshot{}, errors.New("fixture-only sensitive-value /fixture/private")
	}, nil, auth)
	response := httptest.NewRecorder()
	request := loopbackRequest("GET", "/api/v1/system", nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != 503 || strings.Contains(response.Body.String(), "sensitive-value") || strings.Contains(response.Body.String(), "fixture/private") {
		t.Fatal("underlying error leaked")
	}
}

func TestConcurrentRequestLimit(t *testing.T) {
	auth, cookie := newTestAuth(t)
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	handler := newHandler(func() (systemSnapshot, error) {
		entered <- struct{}{}
		<-release
		return collectSystem(fixtureProc(), time.Now())
	}, nil, auth)
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			request := loopbackRequest("GET", "/api/v1/system", nil)
			request.AddCookie(cookie)
			handler.ServeHTTP(httptest.NewRecorder(), request)
		}()
	}
	defer workers.Wait()
	defer close(release)
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("request did not enter collector")
		}
	}
	response := httptest.NewRecorder()
	request := loopbackRequest("GET", "/api/v1/system", nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != 503 || response.Header().Get("Content-Type") != "application/json" || !strings.Contains(response.Body.String(), "busy") {
		t.Fatal("concurrent limit not enforced")
	}
}

func TestServerIsLoopbackAndBounded(t *testing.T) {
	server := newServer(newHandler(nil, nil, nil))
	if server.Addr != "127.0.0.1:8080" || server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes != 8192 || !server.DisableGeneralOptionsHandler {
		t.Fatal("unsafe server defaults")
	}
}

func TestDashboardServesReadOnlyDevelopmentUIAndAssets(t *testing.T) {
	var collectorCalls int
	handler := newHandler(func() (systemSnapshot, error) {
		collectorCalls++
		return collectSystem(fixtureProc(), time.Now())
	}, func() (storageSnapshot, error) {
		collectorCalls++
		return collectStorage(fixtureSysfs())
	}, nil)

	for _, test := range []struct {
		path        string
		contentType string
		contains    []string
	}{
		{"/", "text/html; charset=utf-8", []string{"PhantoWD", "Development image.", "read-only", "profile-notice-title"}},
		{"/assets/app.css", "text/css; charset=utf-8", []string{"@media", "prefers-reduced-motion"}},
		{"/assets/app.js", "text/javascript; charset=utf-8", []string{"/api/v1/system", "/api/v1/storage", "/api/v1/arrays", "/api/v1/mounts", "textContent"}},
		{"/assets/service-policy.js", "text/javascript; charset=utf-8", []string{"sameServiceDocument", "saveServiceAddition"}},
	} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, httptest.NewRequest("GET", test.path, nil))
			if response.Code != 200 || response.Header().Get("Content-Type") != test.contentType {
				t.Fatalf("unexpected dashboard response: status=%d content-type=%q body=%q", response.Code, response.Header().Get("Content-Type"), response.Body.String())
			}
			if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
				t.Fatal("dashboard response is missing no-cache/security headers")
			}
			if test.path == "/" {
				if response.Header().Get("Content-Security-Policy") != "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'" {
					t.Fatal("dashboard CSP is not restrictive")
				}
				if strings.Contains(response.Body.String(), "<script>") || strings.Contains(response.Body.String(), " onload=") {
					t.Fatal("dashboard contains inline executable markup")
				}
			}
			for _, fragment := range test.contains {
				if !strings.Contains(response.Body.String(), fragment) {
					t.Fatalf("dashboard asset %q is missing %q", test.path, fragment)
				}
			}
		})
	}
	if collectorCalls != 0 {
		t.Fatalf("loading static dashboard performed %d live observations", collectorCalls)
	}
	for _, test := range []struct {
		method string
		path   string
		body   string
		status int
	}{
		{http.MethodPost, "/", "", http.StatusMethodNotAllowed},
		{http.MethodGet, "/assets/app.css?file=/etc/passwd", "", http.StatusBadRequest},
		{http.MethodGet, "/assets/app.js", "unexpected", http.StatusBadRequest},
	} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(test.method, test.path, strings.NewReader(test.body)))
		if response.Code != test.status || collectorCalls != 0 {
			t.Fatalf("dashboard accepted non-read request method=%s path=%s status=%d observations=%d", test.method, test.path, response.Code, collectorCalls)
		}
	}
}

func TestStorageEndpointIsReadOnlyAndFailClosed(t *testing.T) {
	auth, cookie := newTestAuth(t)
	var storageCalls int
	handler := newHandler(nil, func() (storageSnapshot, error) {
		storageCalls++
		return collectStorage(fixtureSysfs())
	}, auth)
	response := httptest.NewRecorder()
	request := loopbackRequest("GET", "/api/v1/storage", nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != 200 || storageCalls != 1 || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("valid read failed: status=%d calls=%d body=%s", response.Code, storageCalls, response.Body.String())
	}
	var snapshot storageSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if !snapshot.InventoryReadOnly || snapshot.BlockDevicesOpened || snapshot.ContentRead || snapshot.MutationsPerformed || snapshot.StableIdentityAvailable {
		t.Fatalf("endpoint reported an unsafe or overstated storage operation: %+v", snapshot)
	}
	for _, test := range []struct {
		method string
		path   string
		status int
	}{
		{method: "POST", path: "/api/v1/storage", status: 405},
		{method: "GET", path: "/api/v1/storage?device=/dev/sda", status: 400},
	} {
		response := httptest.NewRecorder()
		request := loopbackRequest(test.method, test.path, nil)
		request.AddCookie(cookie)
		handler.ServeHTTP(response, request)
		if response.Code != test.status || storageCalls != 1 {
			t.Fatalf("unsafe storage request was accepted: method=%s path=%s status=%d calls=%d", test.method, test.path, response.Code, storageCalls)
		}
	}

	failing := newHandler(nil, func() (storageSnapshot, error) {
		return storageSnapshot{}, errors.New("private path and serial fixture-secret")
	}, auth)
	response = httptest.NewRecorder()
	request = loopbackRequest("GET", "/api/v1/storage", nil)
	request.AddCookie(cookie)
	failing.ServeHTTP(response, request)
	if response.Code != 503 || strings.Contains(response.Body.String(), "private path") || strings.Contains(response.Body.String(), "fixture-secret") {
		t.Fatal("storage collector error leaked through the API")
	}
}

func TestMDArrayEndpointIsAuthenticatedReadOnlyAndBounded(t *testing.T) {
	auth, cookie := newTestAuth(t)
	calls := 0
	handler := newHandlerWithArrays(nil, nil, func() mdArraySnapshot {
		calls++
		return collectMDArrayInventory(fstest.MapFS{
			"mdstat": {Data: []byte("Personalities : [raid1]\nunused devices: <none>\n")},
		}, emptySysfs(), time.Now())
	}, auth)

	response := httptest.NewRecorder()
	request := loopbackRequest(http.MethodGet, "/api/v1/arrays", nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls != 1 || !json.Valid(response.Body.Bytes()) {
		t.Fatalf("valid array inventory read failed: status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	var snapshot mdArraySnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.Status != arrayInventoryAvailable || snapshot.ArrayCount != 0 || snapshot.Arrays == nil ||
		!snapshot.ReadOnly || snapshot.BlockDevicesOpened || snapshot.DiskContentRead || snapshot.MutationsPerformed {
		t.Fatalf("endpoint misreported the bounded read-only inventory: %+v", snapshot)
	}

	for _, test := range []struct {
		method string
		path   string
		cookie bool
		status int
	}{
		{method: http.MethodPost, path: "/api/v1/arrays", cookie: true, status: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/api/v1/arrays?device=/dev/sda", cookie: true, status: http.StatusBadRequest},
		{method: http.MethodGet, path: "/api/v1/arrays", status: http.StatusUnauthorized},
	} {
		response := httptest.NewRecorder()
		request := loopbackRequest(test.method, test.path, nil)
		if test.cookie {
			request.AddCookie(cookie)
		}
		handler.ServeHTTP(response, request)
		if response.Code != test.status || calls != 1 {
			t.Fatalf("unsafe array request was accepted: method=%s path=%s status=%d calls=%d", test.method, test.path, response.Code, calls)
		}
	}
}

func TestMountEndpointIsAuthenticatedReadOnlyAndRedacted(t *testing.T) {
	auth, cookie := newTestAuth(t)
	calls := 0
	handler := newHandlerWithMounts(nil, nil, nil, func() (mountSnapshot, error) {
		calls++
		return collectMountInventory(fstest.MapFS{
			"self/mountinfo": {Data: []byte("36 35 8:0 / /media/data rw,relatime - ext4 /dev/sda1 rw\n")},
		}, time.Now())
	}, auth)

	response := httptest.NewRecorder()
	request := loopbackRequest(http.MethodGet, "/api/v1/mounts", nil)
	request.AddCookie(cookie)
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK || calls != 1 || !json.Valid(response.Body.Bytes()) ||
		strings.Contains(response.Body.String(), "/dev/sda1") || strings.Contains(response.Body.String(), "relatime") {
		t.Fatalf("valid mount inventory leaked or failed: status=%d calls=%d body=%s", response.Code, calls, response.Body.String())
	}
	var snapshot mountSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.MountCount != 1 || snapshot.Mounts == nil ||
		!snapshot.ReadOnly || snapshot.FilesystemContentsRead || snapshot.MountOperationsPerformed {
		t.Fatalf("mount endpoint overstated the read-only inventory: %+v", snapshot)
	}

	for _, test := range []struct {
		method string
		path   string
		cookie bool
		status int
	}{
		{method: http.MethodPost, path: "/api/v1/mounts", cookie: true, status: http.StatusMethodNotAllowed},
		{method: http.MethodGet, path: "/api/v1/mounts?path=/dev/sda", cookie: true, status: http.StatusBadRequest},
		{method: http.MethodGet, path: "/api/v1/mounts", status: http.StatusUnauthorized},
	} {
		response := httptest.NewRecorder()
		request := loopbackRequest(test.method, test.path, nil)
		if test.cookie {
			request.AddCookie(cookie)
		}
		handler.ServeHTTP(response, request)
		if response.Code != test.status || calls != 1 {
			t.Fatalf("unsafe mount request was accepted: method=%s path=%s status=%d calls=%d", test.method, test.path, response.Code, calls)
		}
	}

	failing := newHandlerWithMounts(nil, nil, nil, func() (mountSnapshot, error) {
		return mountSnapshot{}, errors.New("private path /secret and source /dev/sda1")
	}, auth)
	response = httptest.NewRecorder()
	request = loopbackRequest(http.MethodGet, "/api/v1/mounts", nil)
	request.AddCookie(cookie)
	failing.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "/secret") || strings.Contains(response.Body.String(), "/dev/sda1") {
		t.Fatal("mount collector error leaked through the API")
	}
}
