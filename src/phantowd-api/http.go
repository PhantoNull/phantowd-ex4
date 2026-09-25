// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"time"
)

const listenAddress = defaultListenAddress

type collector func() (systemSnapshot, error)
type storageSnapshotCollector func() (storageSnapshot, error)
type mdArraySnapshotCollector func() mdArraySnapshot
type mountSnapshotCollector func() (mountSnapshot, error)

func newHandler(collect collector, collectStorage storageSnapshotCollector, auth *authController) http.Handler {
	return newHandlerWithArrays(collect, collectStorage, nil, auth)
}

func newHandlerWithArrays(collect collector, collectStorage storageSnapshotCollector, collectArrays mdArraySnapshotCollector, auth *authController) http.Handler {
	return newHandlerWithMounts(collect, collectStorage, collectArrays, nil, auth)
}

func newHandlerWithMounts(collect collector, collectStorage storageSnapshotCollector, collectArrays mdArraySnapshotCollector, collectMounts mountSnapshotCollector, auth *authController) http.Handler {
	active := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
			return
		}
		if isDashboardPath(r.URL.Path) {
			serveDashboardAsset(w, r)
			return
		}
		if r.URL.Path == "/healthz" {
			if r.Method != http.MethodGet {
				w.Header().Set("Allow", http.MethodGet)
				writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
				return
			}
			if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unexpected_input"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "scope": "process_only"})
			return
		}
		if auth != nil && auth.isAuthPath(r.URL.Path) {
			auth.serve(w, r)
			return
		}
		if r.URL.Path != "/api/v1/system" && r.URL.Path != "/api/v1/storage" && r.URL.Path != "/api/v1/arrays" && r.URL.Path != "/api/v1/mounts" {
			writeJSON(w, http.StatusNotFound, map[string]string{"error": "not_found"})
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unexpected_input"})
			return
		}
		if auth == nil || !auth.authorize(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			return
		}
		if r.URL.Path == "/api/v1/storage" {
			snapshot, err := collectStorage()
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_unavailable"})
				return
			}
			writeJSON(w, http.StatusOK, snapshot)
			return
		}
		if r.URL.Path == "/api/v1/arrays" {
			if collectArrays == nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "array_inventory_unavailable"})
				return
			}
			writeJSON(w, http.StatusOK, collectArrays())
			return
		}
		if r.URL.Path == "/api/v1/mounts" {
			if collectMounts == nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mount_inventory_unavailable"})
				return
			}
			snapshot, err := collectMounts()
			if err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "mount_inventory_unavailable"})
				return
			}
			writeJSON(w, http.StatusOK, snapshot)
			return
		}
		snapshot, err := collect()
		if err != nil {
			// Never expose filesystem paths, raw proc content, or underlying errors.
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "diagnostics_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, snapshot)
	})
}

func isDashboardPath(path string) bool {
	switch path {
	case "/", "/assets/app.css", "/assets/app.js", "/assets/ghost.svg":
		return true
	default:
		return false
	}
}

func serveDashboardAsset(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		w.Header().Set("Allow", http.MethodGet)
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unexpected_input"})
		return
	}

	assetPath, contentType := dashboardAsset(r.URL.Path)
	data, err := fs.ReadFile(dashboardFiles, assetPath)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "dashboard_unavailable"})
		return
	}
	w.Header().Set("Content-Type", contentType)
	if r.URL.Path == "/" {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
	} else {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func dashboardAsset(path string) (string, string) {
	switch path {
	case "/":
		return "ui/index.html", "text/html; charset=utf-8"
	case "/assets/app.css":
		return "ui/app.css", "text/css; charset=utf-8"
	case "/assets/app.js":
		return "ui/app.js", "text/javascript; charset=utf-8"
	case "/assets/ghost.svg":
		return "ui/ghost.svg", "image/svg+xml"
	default:
		return "", "application/octet-stream"
	}
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func newServer(handler http.Handler) *http.Server {
	return newConfiguredServer(handler, apiTransportConfig{
		Address: listenAddress, AllowedOrigin: defaultPublicOrigin,
	})
}

func newConfiguredServer(handler http.Handler, transport apiTransportConfig) *http.Server {
	return &http.Server{
		Addr: transport.Address, Handler: handler, TLSConfig: transport.TLSConfig,
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 8 * 1024, DisableGeneralOptionsHandler: true,
	}
}
