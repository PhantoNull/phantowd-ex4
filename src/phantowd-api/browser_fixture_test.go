// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// TestDashboardBrowserAPIFixture is opt-in, test-binary-only and never packaged.
// It uses the actual handlers, sessions and Argon2id, but only an in-memory
// account backend and invented system data. No real proc/sysfs/storage reads.
func TestDashboardBrowserAPIFixture(t *testing.T) {
	if os.Getenv("PHANTOWD_BROWSER_API_FIXTURE") != "1" {
		t.Skip("explicit host browser fixture only")
	}
	server := httptest.NewUnstartedServer(nil)
	handler, serverAccounts := newBrowserFixtureHandler("http://" + server.Listener.Addr().String())
	defer serverAccounts.Close()
	server.Config.Handler = handler
	server.Config.ReadHeaderTimeout = 5 * time.Second
	server.Config.ReadTimeout = 5 * time.Second
	server.Config.WriteTimeout = 5 * time.Second
	server.Config.IdleTimeout = 5 * time.Second
	server.Config.MaxHeaderBytes = 4096
	server.Start()
	defer server.Close()
	hashes := make(map[string]string)
	for _, name := range []string{"index.html", "app.css", "app.js", "auth.js", "service-policy.js", "support-bundle.js", "ghost.svg"} {
		data, err := dashboardFiles.ReadFile("ui/" + name)
		if err != nil || len(data) > 65536 {
			t.Fatal("fixture asset unavailable or oversized")
		}
		hashes[name] = fmt.Sprintf("%x", sha256.Sum256(data))
	}
	encoded, err := json.Marshal(hashes)
	if err != nil {
		t.Fatal("fixture asset manifest unavailable")
	}
	fmt.Printf("Dashboard API fixture at %s/ (test-only authentication)\n", server.URL)
	fmt.Printf("PHANTOWD_BROWSER_API_ASSETS %s\n", encoded)
	stop := make(chan bool, 1)
	go func() {
		var signal [1]byte
		_, err := io.ReadFull(os.Stdin, signal[:])
		stop <- err == nil && signal[0] == 4
	}()
	select {
	case ok := <-stop:
		if !ok {
			t.Fatal("fixture stop was not explicit")
		}
	case <-time.After(80 * time.Second):
		t.Fatal("fixture lifetime exceeded")
	}
	server.Close()
	if err := serverAccounts.Close(); err != nil {
		t.Fatal("fixture account disposal failed")
	}
	fmt.Println("PHANTOWD_BROWSER_API_STOPPED account=memory-only")
}

func newBrowserFixtureHandler(origin string) (http.Handler, *accountStore) {
	accounts := &accountStore{backend: &memoryAccountBackend{}}
	auth := newAuthController(accounts, origin)
	return newHandler(func() (systemSnapshot, error) {
		snapshot, err := collectSystem(fixtureProc(), time.Now())
		snapshot.Target = "browser-auth-fixture"
		return snapshot, err
	}, func() (storageSnapshot, error) {
		return storageSnapshot{}, errors.New("browser fixture storage unavailable")
	}, auth), accounts
}

func TestBrowserFixtureDiagnosticsStaySynthetic(t *testing.T) {
	handler, accounts := newBrowserFixtureHandler(defaultPublicOrigin)
	defer accounts.Close()
	before := httptest.NewRecorder()
	handler.ServeHTTP(before, loopbackRequest("GET", "/api/v1/system", nil))
	if before.Code != http.StatusUnauthorized {
		t.Fatal("fixture bypassed authentication")
	}
	setup := httptest.NewRecorder()
	request := loopbackRequest("POST", authSetupPath, strings.NewReader(`{"username":"browser-admin","password":"browser fixture original passphrase"}`))
	request.Header.Set("Origin", defaultPublicOrigin)
	request.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setup, request)
	cookies := setup.Result().Cookies()
	if setup.Code != http.StatusCreated || len(cookies) != 1 {
		t.Fatal("fixture did not use actual account enrollment")
	}
	for _, route := range []string{"/api/v1/system", "/api/v1/storage", "/api/v1/arrays", "/api/v1/mounts"} {
		request := loopbackRequest("GET", route, nil)
		request.AddCookie(cookies[0])
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if route != "/api/v1/system" {
			// Missing collectors are unavailable, never real host observations.
			if response.Code != http.StatusServiceUnavailable {
				t.Fatal("fixture admitted a storage observer")
			}
			continue
		}
		var snapshot systemSnapshot
		if response.Code != http.StatusOK || json.Unmarshal(response.Body.Bytes(), &snapshot) != nil ||
			snapshot.Kernel != "6.18.53" ||
			snapshot.Memory.TotalBytes != 268435456 || snapshot.Flashable || snapshot.HardwareValidated {
			t.Fatal("fixture lost its synthetic system boundary")
		}
		if snapshot.Target != "browser-auth-fixture" {
			t.Fatalf("wrong browser-auth fixture profile: %q", snapshot.Target)
		}
	}
}
