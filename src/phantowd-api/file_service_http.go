// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
)

const fileServicePreviewPath = "/api/v1/file-services/preview"

func newFileServicePreviewHandler(auth *authController) http.HandlerFunc {
	// One preview at a time bounds JSON/render memory independently of the
	// general eight-request gate. Do not queue whole request bodies in memory.
	active := make(chan struct{}, 1)
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if auth == nil || !auth.authorize(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			return
		}
		if !validOrigin(r, auth.allowedOrigin) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
			return
		}
		if len(r.Header.Values("X-PhantoWD-CSRF")) != 1 || !auth.validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_validation_failed"})
			return
		}
		if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_preview_request"})
			return
		}
		media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
		charset, hasCharset := parameters["charset"]
		if err != nil || media != "application/json" || len(parameters) > 1 ||
			(len(parameters) == 1 && (!hasCharset || !strings.EqualFold(charset, "utf-8"))) {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_preview_request"})
			return
		}
		if r.ContentLength > fileservice.MaxInputBytes {
			writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "preview_request_too_large"})
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "preview_busy"})
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fileservice.MaxInputBytes))
		if err != nil {
			var tooLarge *http.MaxBytesError
			if errors.As(err, &tooLarge) {
				writeJSON(w, http.StatusRequestEntityTooLarge, map[string]string{"error": "preview_request_too_large"})
			} else {
				writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_preview_request"})
			}
			return
		}
		preview, err := fileservice.Decode(data)
		if err != nil {
			status, code := http.StatusUnprocessableEntity, "invalid_preview_policy"
			switch {
			case errors.Is(err, fileservice.ErrEnvelope):
				status, code = http.StatusBadRequest, "invalid_preview_request"
			case errors.Is(err, fileservice.ErrShares):
				code = "invalid_share_configuration"
			case errors.Is(err, fileservice.ErrSamba):
				code = "unsupported_samba_configuration"
			case errors.Is(err, fileservice.ErrNFS):
				code = "invalid_nfs_configuration"
			}
			writeJSON(w, status, map[string]string{"error": code})
			return
		}
		writeJSON(w, http.StatusOK, preview)
	}
}
