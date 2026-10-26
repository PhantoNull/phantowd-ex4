//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

type nasStateResponse struct {
	SchemaVersion       int               `json:"schema_version"`
	Scope               string            `json:"scope"`
	Revision            uint64            `json:"revision"`
	Configuration       *naspolicy.Config `json:"configuration,omitempty"`
	Saved               bool              `json:"saved"`
	Applied             bool              `json:"applied"`
	ActivationAvailable bool              `json:"activation_available"`
}

// Only snapshot/commit authority is captured at construction. The handler never
// opens/provisions state, reconnects, releases claims, closes its authority or
// applies services. Product bootstrap/default router do not configure it yet.
type nasStateAuthority interface {
	Snapshot(context.Context) (naspolicy.Config, error)
	Commit(context.Context, uint64, naspolicy.Config) error
}

func newNASStateHandler(auth *authController, state nasStateAuthority) http.HandlerFunc {
	active := make(chan struct{}, 1)
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		summary := r.URL.Path == nasSummaryPath
		if r.URL.Path != nasStatePath && !summary {
			writeJSON(w, 404, map[string]string{"error": "not_found"})
			return
		}
		if r.Method != http.MethodGet && (summary || r.Method != http.MethodPut) {
			allow := "GET, PUT"
			if summary {
				allow = "GET"
			}
			w.Header().Set("Allow", allow)
			writeJSON(w, 405, map[string]string{"error": "method_not_allowed"})
			return
		}
		if auth == nil || !auth.authorize(r) {
			writeJSON(w, 401, map[string]string{"error": "authentication_required"})
			return
		}
		check := r
		if r.Method == http.MethodGet && len(r.Header.Values("Origin")) == 0 {
			check = r.Clone(r.Context())
			check.Header.Set("Origin", auth.allowedOrigin)
		}
		if !validOrigin(check, auth.allowedOrigin) {
			writeJSON(w, 403, map[string]string{"error": "origin_not_allowed"})
			return
		}
		if r.Method == http.MethodPut && (len(r.Header.Values("X-PhantoWD-CSRF")) != 1 || !auth.validateCSRF(r)) {
			writeJSON(w, 403, map[string]string{"error": "csrf_validation_failed"})
			return
		}
		if r.Method == http.MethodGet {
			if !readRequestHasNoInput(w, r) {
				return
			}
		} else if !validServiceStateWriteLimit(w, r, naspolicy.MaxInputBytes) {
			return
		}
		if state == nil {
			writeJSON(w, 503, map[string]string{"error": "nas_configuration_not_configured"})
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 503, map[string]string{"error": "nas_configuration_busy"})
			return
		}
		reply := nasStateResponse{SchemaVersion: 1, Scope: "stored-desired-nas-policy-only"}
		if r.Method == http.MethodGet {
			c, err := state.Snapshot(r.Context())
			if err != nil {
				nasStateError(w, err)
				return
			}
			if !auth.authorize(r) {
				writeJSON(w, 401, map[string]string{"error": "authentication_required"})
				return
			}
			if summary {
				if c.Validate() != nil {
					nasStateError(w, naspolicystore.ErrInvalid)
					return
				}
				luns := 0
				for _, target := range c.ISCSI.Targets {
					luns += len(target.LUNs)
				}
				writeJSON(w, 200, map[string]any{"schema_version": 1, "scope": "stored-desired-nas-policy-summary-only", "revision": c.Revision,
					"volumes": len(c.FileServices.Shares.Volumes), "users": len(c.FileServices.Shares.Users),
					"smb_shares": len(c.FileServices.Shares.Shares), "nfs_exports": len(c.FileServices.NFS.Exports),
					"iscsi_targets": len(c.ISCSI.Targets), "iscsi_backings": len(c.ISCSI.Backings), "iscsi_luns": luns,
					"applied": false, "activation_available": false})
				return
			}
			reply.Revision, reply.Configuration = c.Revision, &c
		} else {
			data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, naspolicy.MaxInputBytes))
			if err != nil {
				status := http.StatusBadRequest
				var large *http.MaxBytesError
				if errors.As(err, &large) {
					status = http.StatusRequestEntityTooLarge
				}
				writeJSON(w, status, map[string]string{"error": "invalid_nas_configuration_request"})
				return
			}
			c, err := naspolicy.Decode(bytes.NewReader(data))
			if err != nil {
				writeJSON(w, 422, map[string]string{"error": "invalid_nas_configuration"})
				return
			}
			if r.Context().Err() != nil {
				writeJSON(w, 400, map[string]string{"error": "request_cancelled"})
				return
			}
			if !auth.authorize(r) || !auth.validateCSRF(r) {
				writeJSON(w, 401, map[string]string{"error": "authentication_required"})
				return
			}
			if err := state.Commit(r.Context(), c.Revision-1, c); err != nil {
				nasStateError(w, err)
				return
			}
			reply.Revision, reply.Saved = c.Revision, true
		}
		writeJSON(w, 200, reply)
	}
}

func nasStateError(w http.ResponseWriter, err error) {
	status, code := 503, "nas_configuration_unavailable"
	switch {
	case errors.Is(err, naspolicystore.ErrConflict):
		status, code = 409, "nas_configuration_conflict"
	case errors.Is(err, naspolicystore.ErrBusy):
		code = "nas_configuration_busy"
		w.Header().Set("Retry-After", "1")
	case errors.Is(err, naspolicystore.ErrReview), errors.Is(err, naspolicystore.ErrUncertain):
		code = "nas_configuration_reconciliation_required"
	}
	writeJSON(w, status, map[string]string{"error": code})
}
