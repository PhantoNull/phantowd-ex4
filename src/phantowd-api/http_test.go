// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
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
	accounts := openTestAccountStore(t, dir)
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
		{"/assets/service-policy.js", "text/javascript; charset=utf-8", []string{"sameServiceDocument", "saveServiceChange"}},
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

func TestStorageEndpointReportsDuplicateVPDAsAmbiguousWithoutValues(t *testing.T) {
	naaA := []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 1}
	naaB := []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2}
	for _, test := range []struct {
		name       string
		serialA    string
		serialB    string
		wwnA       []byte
		wwnB       []byte
		wantSerial identityStatus
		wantWWN    identityStatus
	}{
		{
			name: "duplicate serial", serialA: "http-private-serial-shared", serialB: "http-private-serial-shared",
			wwnA: naaA, wwnB: naaB, wantSerial: identityAmbiguous, wantWWN: identityPresent,
		},
		{
			name: "duplicate WWN", serialA: "http-private-serial-a", serialB: "http-private-serial-b",
			wwnA: naaA, wwnB: naaA, wantSerial: identityPresent, wantWWN: identityAmbiguous,
		},
		{
			name: "duplicate serial and WWN", serialA: "http-private-serial-shared", serialB: "http-private-serial-shared",
			wwnA: naaA, wwnB: naaA, wantSerial: identityAmbiguous, wantWWN: identityAmbiguous,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			sysfs := fixtureSysfs()
			addNonPartitionBlockNode(sysfs, "sdb", 8, 16, test.serialB, test.wwnB)
			sysfs["class/block/sda/device/vpd_pg80"] = &fstest.MapFile{Data: makeVPDPage(0x80, []byte(test.serialA))}
			sysfs["class/block/sda/device/vpd_pg83"] = &fstest.MapFile{Data: makeNAAPage(test.wwnA)}
			auth, cookie := newTestAuth(t)
			handler := newHandler(nil, func() (storageSnapshot, error) {
				return collectStorage(sysfs)
			}, auth)
			request := loopbackRequest(http.MethodGet, "/api/v1/storage", nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusOK || !json.Valid(response.Body.Bytes()) {
				t.Fatalf("storage API request failed: status=%d body=%s", response.Code, response.Body.String())
			}

			var snapshot storageSnapshot
			if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
				t.Fatal(err)
			}
			if !snapshot.InventoryReadOnly || snapshot.BlockDevicesOpened || snapshot.ContentRead ||
				snapshot.MutationsPerformed || snapshot.StableIdentityAvailable {
				t.Fatalf("storage API overstated its observation: %+v", snapshot)
			}
			var found int
			for _, observation := range snapshot.Observations {
				if observation.Name != "sda" && observation.Name != "sdb" {
					continue
				}
				found++
				if observation.SerialStatus != test.wantSerial || observation.WWNStatus != test.wantWWN {
					t.Fatalf("API did not publish duplicate status for %s: %+v", observation.Name, observation)
				}
			}
			if found != 2 {
				t.Fatalf("expected both fixture block nodes in API response, found %d", found)
			}
			for _, secret := range []string{
				test.serialA, test.serialB,
				"500f000000000001", "500f000000000002",
			} {
				if strings.Contains(response.Body.String(), secret) {
					t.Fatalf("storage API leaked VPD value %q: %s", secret, response.Body.String())
				}
			}
		})
	}
}

func TestStorageEndpointDoesNotPublishInconsistentVPDInventory(t *testing.T) {
	base := fixtureSysfs()
	addNonPartitionBlockNode(
		base, "sdb", 8, 16, "PHANTOWD-QEMU-SERIAL-01", []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2},
	)
	sysfs := &changingStorageAttributeFS{
		MapFS: base,
		path:  "class/block/sdb/device/vpd_pg80",
		first: string(makeVPDPage(0x80, []byte("PHANTOWD-QEMU-SERIAL-01"))),
		later: string(makeVPDPage(0x80, []byte("replacement-serial"))),
	}
	auth, cookie := newTestAuth(t)
	handler := newHandler(nil, func() (storageSnapshot, error) {
		return collectStorage(sysfs)
	}, auth)
	request := loopbackRequest(http.MethodGet, "/api/v1/storage", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unstable storage snapshot returned status %d: %s", response.Code, response.Body.String())
	}
	var failure map[string]string
	if err := json.Unmarshal(response.Body.Bytes(), &failure); err != nil {
		t.Fatalf("storage failure was not JSON: %v", err)
	}
	if len(failure) != 1 || failure["error"] != "storage_unavailable" ||
		strings.Contains(response.Body.String(), "observations") ||
		strings.Contains(response.Body.String(), "PHANTOWD-QEMU-SERIAL-01") ||
		strings.Contains(response.Body.String(), "replacement-serial") {
		t.Fatalf("inconsistent or sensitive storage data escaped the API: %s", response.Body.String())
	}
}

func TestStorageEndpointDoesNotCallRepeatedInvalidVPDIdentitiesAmbiguous(t *testing.T) {
	sysfs := fixtureSysfs()
	addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "private-invalid-serial\x00", make([]byte, 8))
	invalidSerialPage := makeVPDPage(0x80, []byte("private-invalid-serial\x00"))
	invalidWWNPage := makeNAAPage(make([]byte, 8))
	for _, device := range []string{"sda", "sdb"} {
		base := "class/block/" + device + "/device/"
		sysfs[base+"vpd_pg80"] = &fstest.MapFile{Data: invalidSerialPage}
		sysfs[base+"vpd_pg83"] = &fstest.MapFile{Data: invalidWWNPage}
	}

	auth, cookie := newTestAuth(t)
	handler := newHandler(nil, func() (storageSnapshot, error) {
		return collectStorage(sysfs)
	}, auth)
	request := loopbackRequest(http.MethodGet, "/api/v1/storage", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("storage API failed: status=%d body=%s", response.Code, response.Body.String())
	}

	var snapshot storageSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	var found int
	for _, observation := range snapshot.Observations {
		if observation.Name != "sda" && observation.Name != "sdb" {
			continue
		}
		found++
		if observation.SerialStatus != identityInvalid || observation.WWNStatus != identityInvalid {
			t.Fatalf("repeated invalid VPD identities were not kept invalid: %+v", observation)
		}
	}
	if found != 2 {
		t.Fatalf("expected both synthetic disks in API response, found %d", found)
	}
	if strings.Contains(response.Body.String(), "private-invalid-serial") || strings.Contains(response.Body.String(), "0000000000000000") {
		t.Fatalf("invalid raw VPD values leaked through the API: %s", response.Body.String())
	}
}

func TestStorageEndpointDoesNotCountPartitionVPDAsDiskCollision(t *testing.T) {
	naaA := []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 1}
	naaB := []byte{0x50, 0x0f, 0, 0, 0, 0, 0, 2}
	sysfs := fixtureSysfs()
	addNonPartitionBlockNode(sysfs, "sdb", 8, 16, "private-serial-b", naaB)
	partitionBase := "class/block/sda1/device/"
	sysfs[partitionBase] = &fstest.MapFile{Mode: fs.ModeDir | 0o555}
	sysfs[partitionBase+"vpd_pg80"] = &fstest.MapFile{Data: makeVPDPage(0x80, []byte("PHANTOWD-QEMU-SERIAL-01"))}
	sysfs[partitionBase+"vpd_pg83"] = &fstest.MapFile{Data: makeNAAPage(naaA)}

	auth, cookie := newTestAuth(t)
	handler := newHandler(nil, func() (storageSnapshot, error) {
		return collectStorage(sysfs)
	}, auth)
	request := loopbackRequest(http.MethodGet, "/api/v1/storage", nil)
	request.AddCookie(cookie)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("storage API failed: status=%d body=%s", response.Code, response.Body.String())
	}

	var snapshot storageSnapshot
	if err := json.Unmarshal(response.Body.Bytes(), &snapshot); err != nil {
		t.Fatal(err)
	}
	observations := make(map[string]blockObservation, 3)
	for _, observation := range snapshot.Observations {
		if observation.Name == "sda" || observation.Name == "sda1" || observation.Name == "sdb" {
			observations[observation.Name] = observation
		}
	}
	for _, name := range []string{"sda", "sdb"} {
		observation, ok := observations[name]
		if !ok || observation.SerialStatus != identityPresent || observation.WWNStatus != identityPresent {
			t.Fatalf("partition metadata caused a false whole-disk collision for %s: %+v", name, observation)
		}
	}
	partition, ok := observations["sda1"]
	if !ok || partition.Kind != "partition" || partition.SerialStatus != "" || partition.WWNStatus != "" {
		t.Fatalf("partition acquired whole-disk VPD collision status: %+v", partition)
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
