// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

const iscsiPreviewPath = "/api/v1/iscsi/preview"

// Caller-supplied desired policy only. This handler has no store, collector,
// credential resolver, backing opener or target backend to invoke.
func newISCSIPreviewHandler(auth *authController) http.HandlerFunc {
	active := make(chan struct{}, 1)
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if auth == nil || !auth.authorize(r) {
			writeJSON(w, 401, map[string]string{"error": "authentication_required"})
			return
		}
		if !validOrigin(r, auth.allowedOrigin) {
			writeJSON(w, 403, map[string]string{"error": "origin_not_allowed"})
			return
		}
		if len(r.Header.Values("X-PhantoWD-CSRF")) != 1 || !auth.validateCSRF(r) {
			writeJSON(w, 403, map[string]string{"error": "csrf_validation_failed"})
			return
		}
		// Reuse only the existing strict HTTP envelope check, not a writer.
		if !validServiceStateWriteLimit(w, r, naspolicy.MaxInputBytes) {
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 503, map[string]string{"error": "iscsi_preview_busy"})
			return
		}
		if r.Context().Err() != nil {
			writeJSON(w, 408, map[string]string{"error": "iscsi_preview_canceled"})
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, naspolicy.MaxInputBytes))
		defer clear(data)
		if err != nil {
			status := http.StatusBadRequest
			var large *http.MaxBytesError
			if errors.As(err, &large) {
				status = http.StatusRequestEntityTooLarge
			}
			writeJSON(w, status, map[string]string{"error": "invalid_iscsi_preview_request"})
			return
		}
		config, err := naspolicy.Decode(bytes.NewReader(data))
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": "invalid_coherent_nas_policy"})
			return
		}
		preview, err := iscsipreview.Build(config)
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": "invalid_iscsi_preview"})
			return
		}
		encoded, err := json.Marshal(preview)
		if err != nil || len(encoded) > iscsipreview.MaxOutputBytes {
			writeJSON(w, 503, map[string]string{"error": "iscsi_preview_unavailable"})
			return
		}
		if r.Context().Err() != nil {
			writeJSON(w, 408, map[string]string{"error": "iscsi_preview_canceled"})
			return
		}
		if !auth.authorize(r) || !auth.validateCSRF(r) {
			writeJSON(w, 401, map[string]string{"error": "authentication_required"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded) // Exact bounded JSON; no extra encoder newline.
	}
}
