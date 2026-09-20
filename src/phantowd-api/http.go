// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"net/http"
	"time"
)

const listenAddress = "127.0.0.1:8080"

type collector func() (systemSnapshot, error)

func newHandler(collect collector) http.Handler {
	active := make(chan struct{}, 8)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "busy"})
			return
		}
		if r.URL.Path != "/healthz" && r.URL.Path != "/api/v1/system" {
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
		if r.URL.Path == "/healthz" {
			writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "scope": "process_only"})
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

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func newServer(handler http.Handler) *http.Server {
	return &http.Server{
		Addr: listenAddress, Handler: handler,
		ReadHeaderTimeout: 3 * time.Second, ReadTimeout: 5 * time.Second,
		WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
		MaxHeaderBytes: 8 * 1024, DisableGeneralOptionsHandler: true,
	}
}
