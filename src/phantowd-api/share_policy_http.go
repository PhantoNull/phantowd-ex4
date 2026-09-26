// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"net/http"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const sharePolicyPath = "/api/v1/shares/configuration"

// nil policy with nil error means explicitly uninitialized storage, not an
// empty configured policy. nil loader means storage was not configured at all.
// Returned snapshots must be independently owned by the caller.
type sharePolicyLoader func() (*shareconfig.Config, error)

type sharePolicyResponse struct {
	SchemaVersion       int                 `json:"schema_version"`
	Scope               string              `json:"scope"`
	Initialized         bool                `json:"initialized"`
	Configuration       *shareconfig.Config `json:"configuration"`
	RuntimeValidated    bool                `json:"runtime_validated"`
	ActivationAvailable bool                `json:"activation_available"`
}

func newSharePolicyReadHandler(auth *authController, load sharePolicyLoader) http.HandlerFunc {
	active := make(chan struct{}, 1)
	return func(w http.ResponseWriter, r *http.Request) {
		if !requireMethod(w, r, http.MethodGet) {
			return
		}
		if auth == nil || !auth.authorize(r) {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
			return
		}
		// Browsers normally omit Origin on same-origin GETs. Still require
		// exact configured Host/scheme; if Origin is present validate it too.
		check := r.Clone(r.Context())
		if len(check.Header.Values("Origin")) == 0 {
			check.Header.Set("Origin", auth.allowedOrigin)
		}
		if !validOrigin(check, auth.allowedOrigin) {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
			return
		}
		if !readRequestHasNoInput(w, r) {
			return
		}
		if load == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "share_configuration_unavailable"})
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "share_configuration_busy"})
			return
		}
		config, err := load()
		if err == nil && config != nil {
			// Defensive validation at the adapter boundary; do not trust a
			// future backend to return bounded, structurally complete policy.
			if err = config.Validate(); err == nil {
				var data []byte
				data, err = json.Marshal(config)
				if err == nil {
					_, err = shareconfig.Decode(bytes.NewReader(data))
				}
			}
		}
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "share_configuration_unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, sharePolicyResponse{
			SchemaVersion: 1, Scope: "stored-desired-share-policy-only", Initialized: config != nil, Configuration: config,
		})
	}
}
