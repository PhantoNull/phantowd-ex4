//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestQEMUShareConfig(t *testing.T) {
	if err := exerciseQEMUShareConfig(); err != nil {
		t.Fatal(err)
	}
}

func TestQEMUDashboardAssetsMatchSelfTest(t *testing.T) {
	for _, asset := range qemuDashboardAssets {
		assetPath, _ := dashboardAsset(asset.path)
		data, err := dashboardFiles.ReadFile(assetPath)
		if err != nil {
			t.Fatalf("read embedded asset %q: %v", asset.path, err)
		}
		for _, marker := range asset.markers {
			if !strings.Contains(string(data), marker) {
				t.Errorf("QEMU self-test marker %q is absent from embedded asset %q", marker, asset.path)
			}
		}
	}
}

func TestQEMUAPIReadinessWaitsWithoutMutatingBeforeReady(t *testing.T) {
	var healthRequests atomic.Int32
	var otherRequests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" || r.Method != http.MethodGet {
			otherRequests.Add(1)
			http.NotFound(w, r)
			return
		}
		if healthRequests.Add(1) < 3 {
			http.Error(w, "starting", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = io.WriteString(w, `{"status":"ok","scope":"process_only"}`)
	}))
	defer server.Close()

	client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if err := waitQEMUAPIReady(client, server.URL); err != nil {
		t.Fatalf("readiness wait failed: %v", err)
	}
	if got := healthRequests.Load(); got != 3 {
		t.Fatalf("expected three read-only readiness probes, got %d", got)
	}
	if got := otherRequests.Load(); got != 0 {
		t.Fatalf("readiness probe reached a non-health endpoint %d times", got)
	}
}
