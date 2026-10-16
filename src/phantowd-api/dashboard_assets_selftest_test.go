//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestQEMUDashboardAssetsHTTPAndTLS(t *testing.T) {
	entries, err := dashboardFiles.ReadDir("ui")
	if err != nil || len(entries) != 8 || len(qemuDashboardAssets) != len(entries) {
		t.Fatal("receipt roster must cover the complete seven-file embedded UI")
	}
	covered := make(map[string]bool)
	for _, asset := range qemuDashboardAssets {
		path, _ := dashboardAsset(asset.path)
		if covered[path] {
			t.Fatal("duplicate dashboard assertion source")
		}
		covered[path] = true
	}
	for _, entry := range entries {
		if entry.IsDir() || !covered["ui/"+entry.Name()] {
			t.Fatal("uncovered embedded UI entry")
		}
	}
	for _, tls := range []bool{false, true} {
		t.Run(map[bool]string{false: "http", true: "https"}[tls], func(t *testing.T) {
			var observations atomic.Int32
			handler := newHandler(func() (systemSnapshot, error) {
				observations.Add(1)
				return systemSnapshot{}, errors.New("not a UI operation")
			}, nil, nil)
			var server *httptest.Server
			if tls {
				server = httptest.NewTLSServer(handler)
			} else {
				server = httptest.NewServer(handler)
			}
			defer server.Close()
			client := server.Client()
			client.Timeout = time.Second
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			defer client.CloseIdleConnections()
			if err := exerciseQEMUDashboardAssets(client, server.URL); err != nil {
				t.Fatal(err)
			}
			if observations.Load() != 0 {
				t.Fatal("asset check collected live observations")
			}
		})
	}
}

type qemuDashboardAssetTransport func(*http.Request) (*http.Response, error)

func (f qemuDashboardAssetTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type qemuDashboardAssetBody struct {
	reader            io.Reader
	readErr, closeErr error
	readBytes         int
	closed            bool
}

func (b *qemuDashboardAssetBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	n, err := b.reader.Read(p)
	b.readBytes += n
	return n, err
}
func (b *qemuDashboardAssetBody) Close() error { b.closed = true; return b.closeErr }

func TestQEMUDashboardAssetsRefusals(t *testing.T) {
	const private = "PRIVATE-DASHBOARD-FAULT"
	for _, tc := range []struct {
		name, path string
		change     func(*http.Response, *qemuDashboardAssetBody)
	}{
		{"status", "/", func(r *http.Response, _ *qemuDashboardAssetBody) { r.StatusCode = 503 }},
		{"redirect", "/", func(r *http.Response, _ *qemuDashboardAssetBody) {
			r.StatusCode = 302
			r.Header.Set("Location", "https://invalid.example/"+private)
		}},
		{"mime", "/", func(r *http.Response, _ *qemuDashboardAssetBody) { r.Header.Set("Content-Type", private) }},
		{"duplicate-mime", "/", func(r *http.Response, _ *qemuDashboardAssetBody) {
			r.Header.Add("Content-Type", r.Header.Get("Content-Type"))
		}},
		{"cache", "/", func(r *http.Response, _ *qemuDashboardAssetBody) { r.Header.Del("Cache-Control") }},
		{"duplicate-cache", "/", func(r *http.Response, _ *qemuDashboardAssetBody) { r.Header.Add("Cache-Control", "no-store") }},
		{"sniff", "/", func(r *http.Response, _ *qemuDashboardAssetBody) { r.Header.Del("X-Content-Type-Options") }},
		{"root-csp", "/", func(r *http.Response, _ *qemuDashboardAssetBody) {
			r.Header.Set("Content-Security-Policy", "default-src *")
		}},
		{"script-csp", "/assets/app.js", func(r *http.Response, _ *qemuDashboardAssetBody) { r.Header.Del("Content-Security-Policy") }},
		{"read", "/", func(_ *http.Response, b *qemuDashboardAssetBody) { b.readErr = errors.New(private) }},
		{"close", "/", func(_ *http.Response, b *qemuDashboardAssetBody) { b.closeErr = errors.New(private) }},
		{"empty", "/", func(_ *http.Response, b *qemuDashboardAssetBody) { b.reader = strings.NewReader("") }},
		{"oversized", "/", func(r *http.Response, b *qemuDashboardAssetBody) {
			r.ContentLength = 0
			b.reader = strings.NewReader(strings.Repeat("x", qemuDashboardAssetLimit+1024))
		}},
		// Every old source marker remains present: only byte equality detects this.
		{"altered-marker-preserving", "/assets/service-policy.js", func(_ *http.Response, b *qemuDashboardAssetBody) {
			b.reader = io.MultiReader(strings.NewReader(" "), b.reader)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var bodies []*qemuDashboardAssetBody
			var paths []string
			client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
				Transport: qemuDashboardAssetTransport(func(r *http.Request) (*http.Response, error) {
					paths = append(paths, r.URL.Path)
					path, contentType := dashboardAsset(r.URL.Path)
					data, err := dashboardFiles.ReadFile(path)
					if err != nil {
						return nil, err
					}
					body := &qemuDashboardAssetBody{reader: bytes.NewReader(data)}
					bodies = append(bodies, body)
					csp := "default-src 'none'; sandbox"
					if r.URL.Path == "/" {
						csp = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
					}
					response := &http.Response{StatusCode: 200, Header: http.Header{}, Body: body, ContentLength: int64(len(data)), Request: r}
					response.Header.Set("Content-Type", contentType)
					response.Header.Set("Cache-Control", "no-store")
					response.Header.Set("X-Content-Type-Options", "nosniff")
					response.Header.Set("Content-Security-Policy", csp)
					if r.URL.Path == tc.path {
						tc.change(response, body)
					}
					return response, nil
				})}
			err := exerciseQEMUDashboardAssets(client, "https://127.0.0.1:1")
			if err == nil || strings.Contains(err.Error(), private) {
				t.Fatalf("fault accepted/leaked: %v", err)
			}
			if paths[len(paths)-1] != tc.path {
				t.Fatalf("failure continued into other assets: %v", paths)
			}
			for _, body := range bodies {
				if !body.closed || body.readBytes > qemuDashboardAssetLimit+1 {
					t.Fatal("response not closed/bounded")
				}
			}
		})
	}
	client := &http.Client{Transport: qemuDashboardAssetTransport(func(*http.Request) (*http.Response, error) { return nil, errors.New(private) })}
	if err := exerciseQEMUDashboardAssets(client, "https://127.0.0.1:1"); err == nil || strings.Contains(err.Error(), private) {
		t.Fatal("request error not redacted")
	}
}
