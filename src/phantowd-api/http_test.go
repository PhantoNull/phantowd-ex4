// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

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
		{"root", "GET", "/", "", 404, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			called := false
			handler := newHandler(func() (systemSnapshot, error) {
				called = true
				return collectSystem(fixtureProc(), time.Now())
			})
			request := httptest.NewRequest(test.method, test.path, strings.NewReader(test.body))
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
	handler := newHandler(func() (systemSnapshot, error) {
		return systemSnapshot{}, errors.New("fixture-only sensitive-value /fixture/private")
	})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/system", nil))
	if response.Code != 503 || strings.Contains(response.Body.String(), "sensitive-value") || strings.Contains(response.Body.String(), "fixture/private") {
		t.Fatal("underlying error leaked")
	}
}

func TestConcurrentRequestLimit(t *testing.T) {
	entered := make(chan struct{}, 8)
	release := make(chan struct{})
	handler := newHandler(func() (systemSnapshot, error) {
		entered <- struct{}{}
		<-release
		return collectSystem(fixtureProc(), time.Now())
	})
	var workers sync.WaitGroup
	for i := 0; i < 8; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/api/v1/system", nil))
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
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/api/v1/system", nil))
	if response.Code != 503 || !strings.Contains(response.Body.String(), "busy") {
		t.Fatal("concurrent limit not enforced")
	}
}

func TestServerIsLoopbackAndBounded(t *testing.T) {
	server := newServer(newHandler(nil))
	if server.Addr != "127.0.0.1:8080" || server.ReadHeaderTimeout <= 0 || server.ReadTimeout <= 0 || server.WriteTimeout <= 0 || server.IdleTimeout <= 0 || server.MaxHeaderBytes != 8192 || !server.DisableGeneralOptionsHandler {
		t.Fatal("unsafe server defaults")
	}
}
