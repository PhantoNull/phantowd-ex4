// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"net/http"
	"time"
)

var errStorageGPTObservationBusy = errors.New("storage GPT observation busy")

const (
	storageGPTObservationTimeout         = 50 * time.Second
	storageGPTObservationResponseTimeout = storageGPTObservationTimeout + 5*time.Second
)

type storageGPTObservationCollector func(context.Context) (storageGPTObservationSummary, error)

func newStorageGPTObservationHandler(auth *authController, collect storageGPTObservationCollector) http.HandlerFunc {
	active := make(chan struct{}, 1)
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodPost) {
			return
		}
		if auth == nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			return
		}
		if !validOrigin(r, auth.allowedOrigin) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
			return
		}
		if !auth.authorize(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			return
		}
		if len(r.Header.Values("X-PhantoWD-CSRF")) != 1 || !auth.validateCSRF(r) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_validation_failed"})
			return
		}
		if !readRequestHasNoInput(w, r) {
			return
		}
		if len(r.Header.Values("Content-Type")) != 0 || len(r.Header.Values("Content-Encoding")) != 0 {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_observation_request"})
			return
		}
		if collect == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_observation_unavailable"})
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_observation_busy"})
			return
		}
		if err := http.NewResponseController(w).SetWriteDeadline(time.Now().Add(storageGPTObservationResponseTimeout)); err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_observation_unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), storageGPTObservationTimeout)
		defer cancel()
		summary, err := collect(ctx)
		if errors.Is(err, errStorageGPTObservationBusy) {
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_observation_busy"})
			return
		}
		if err != nil || !validStorageGPTObservationSummary(summary) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "storage_observation_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, summary)
	}
}
