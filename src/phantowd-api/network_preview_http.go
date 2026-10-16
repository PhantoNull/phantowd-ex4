// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/networkpolicy"
)

const networkPreviewPath = "/api/v1/network/preview"
const networkPreviewLimit = 32 << 10

type networkPreview struct {
	Format                    string                    `json:"format"`
	SchemaVersion             int                       `json:"schema_version"`
	Scope                     string                    `json:"scope"`
	Revision                  string                    `json:"revision"`
	Hostname                  string                    `json:"hostname"`
	Interfaces                []networkpolicy.Interface `json:"interfaces"`
	Routes                    []networkpolicy.Route     `json:"routes"`
	DNS                       networkpolicy.DNS         `json:"dns"`
	Saved                     bool                      `json:"saved"`
	Applied                   bool                      `json:"applied"`
	InterfaceBindingValidated bool                      `json:"interface_binding_validated"`
	KernelStateValidated      bool                      `json:"kernel_state_validated"`
	ConflictsValidated        bool                      `json:"conflicts_validated"`
	ReachabilityValidated     bool                      `json:"reachability_validated"`
	ActivationAvailable       bool                      `json:"activation_available"`
	Limitations               []string                  `json:"limitations"`
}

// No store, kernel collector, resolver, command backend or interface binding is
// supplied. Success validates only the submitted desired-policy document.
func newNetworkPreviewHandler(auth *authController) http.HandlerFunc {
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
		if !validServiceStateWriteLimit(w, r, networkpolicy.MaxInputBytes) {
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 503, map[string]string{"error": "network_preview_busy"})
			return
		}
		canceled := func() bool {
			if r.Context().Err() == nil {
				return false
			}
			writeJSON(w, 408, map[string]string{"error": "network_preview_canceled"})
			return true
		}
		if canceled() {
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, networkpolicy.MaxInputBytes))
		defer clear(data)
		if err != nil {
			status := http.StatusBadRequest
			var large *http.MaxBytesError
			if errors.As(err, &large) {
				status = http.StatusRequestEntityTooLarge
			}
			writeJSON(w, status, map[string]string{"error": "invalid_network_preview_request"})
			return
		}
		p, err := networkpolicy.Decode(bytes.NewReader(data))
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": "invalid_desired_network_policy"})
			return
		}
		preview := networkPreview{Format: "phantowd-desired-network-preview", SchemaVersion: 1, Scope: "submitted-desired-policy-only",
			Revision: strconv.FormatUint(p.Revision, 10), Hostname: p.Hostname, Interfaces: p.Interfaces, Routes: p.Routes, DNS: p.DNS,
			Limitations: []string{
				"Logical lan-1/lan-2 slots are not Linux names, factory MACs or qualified physical sockets.",
				"Configured overlap checks do not establish external address availability, DHCP/RA behavior or routing/DNS reachability.",
				"The revision is supplied syntax, not saved state, compare-and-swap authority or a confirmed network trial.",
				"Nothing is saved or applied. Interface binding, live observations and recoverable trial/rollback remain required.",
			}}
		encoded, err := json.Marshal(preview)
		if err != nil || len(encoded) > networkPreviewLimit {
			writeJSON(w, 503, map[string]string{"error": "network_preview_unavailable"})
			return
		}
		if canceled() {
			return
		}
		if !auth.authorize(r) || !auth.validateCSRF(r) {
			writeJSON(w, 401, map[string]string{"error": "authentication_required"})
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	}
}
