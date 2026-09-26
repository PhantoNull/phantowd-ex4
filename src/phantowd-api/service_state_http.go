// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
)

const serviceStatePath = "/api/v1/file-services/configuration"

var (
	errServiceStateConflict  = errors.New("service state conflict")
	errServiceStateUncertain = errors.New("service state requires reconciliation")
)

// Backend methods return independent validated snapshots. A nil Load result
// means uninitialized, never corruption. Only the QEMU development adapter
// can be configured by main; nil backend fails closed on every platform.
type serviceStateBackend struct {
	load   func() (*fileservice.Config, error)
	commit func(uint64, fileservice.Config) error
}

type serviceStateResponse struct {
	SchemaVersion       int                 `json:"schema_version"`
	Scope               string              `json:"scope"`
	Initialized         bool                `json:"initialized"`
	Configuration       *fileservice.Config `json:"configuration"`
	Applied             bool                `json:"applied"`
	RuntimeValidated    bool                `json:"runtime_validated"`
	ActivationAvailable bool                `json:"activation_available"`
}

func newServiceStateHandler(auth *authController, backend *serviceStateBackend) http.HandlerFunc {
	// Reads and writes share one non-queuing gate so a blocked store does not
	// accumulate HTTP goroutines waiting for its mutex or whole request bodies.
	active := make(chan struct{}, 1)
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPut {
			w.Header().Set("Allow", "GET, PUT")
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
		} else if !validServiceStateWrite(w, r) {
			return
		}
		if backend == nil || backend.load == nil || backend.commit == nil {
			writeJSON(w, 503, map[string]string{"error": "service_configuration_not_configured"})
			return
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			w.Header().Set("Retry-After", "1")
			writeJSON(w, 503, map[string]string{"error": "service_configuration_busy"})
			return
		}
		if r.Method == http.MethodGet {
			c, err := backend.load()
			if err == nil && c != nil {
				// Validate before encoding and apply the strict encoded-size rule.
				err = c.Validate()
				if err == nil {
					var data []byte
					data, err = json.Marshal(c)
					if err == nil {
						_, err = fileservice.DecodeConfig(bytes.NewReader(data))
					}
				}
			}
			if err != nil {
				serviceStateError(w, err)
				return
			}
			writeJSON(w, 200, serviceStateResponse{SchemaVersion: 1, Scope: "development-stored-file-service-policy-only", Initialized: c != nil, Configuration: c})
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fileservice.MaxConfigBytes))
		if err != nil {
			status := http.StatusBadRequest
			var large *http.MaxBytesError
			if errors.As(err, &large) {
				status = http.StatusRequestEntityTooLarge
			}
			writeJSON(w, status, map[string]string{"error": "invalid_service_configuration_request"})
			return
		}
		c, err := fileservice.DecodeConfig(bytes.NewReader(data))
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": "invalid_service_configuration"})
			return
		}
		if r.Context().Err() != nil {
			writeJSON(w, 400, map[string]string{"error": "request_cancelled"})
			return
		}
		// Recheck after bounded body parsing, before a persistent transaction.
		if !auth.authorize(r) || !auth.validateCSRF(r) {
			writeJSON(w, 401, map[string]string{"error": "authentication_required"})
			return
		}
		if err := backend.commit(c.Revision-1, c); err != nil {
			serviceStateError(w, err)
			return
		}
		// Reply only after the backend confirms file+directory sync. A lost
		// reply is not permission to retry blindly: GET and reconcile revision.
		writeJSON(w, 200, struct {
			SchemaVersion       int    `json:"schema_version"`
			Scope               string `json:"scope"`
			Revision            uint64 `json:"revision"`
			Saved               bool   `json:"saved"`
			Applied             bool   `json:"applied"`
			RuntimeValidated    bool   `json:"runtime_validated"`
			ActivationAvailable bool   `json:"activation_available"`
		}{SchemaVersion: 1, Scope: "development-stored-file-service-policy-only", Revision: c.Revision, Saved: true})
	}
}

func validServiceStateWrite(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 {
		writeJSON(w, 400, map[string]string{"error": "invalid_service_configuration_request"})
		return false
	}
	media, parameters, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	charset, hasCharset := parameters["charset"]
	if err != nil || media != "application/json" || len(parameters) > 1 || (len(parameters) == 1 && (!hasCharset || !strings.EqualFold(charset, "utf-8"))) {
		writeJSON(w, 400, map[string]string{"error": "invalid_service_configuration_request"})
		return false
	}
	if r.ContentLength > fileservice.MaxConfigBytes {
		writeJSON(w, 413, map[string]string{"error": "service_configuration_too_large"})
		return false
	}
	return true
}

func serviceStateError(w http.ResponseWriter, err error) {
	status, code := http.StatusServiceUnavailable, "service_configuration_unavailable"
	if errors.Is(err, errServiceStateConflict) {
		status, code = http.StatusConflict, "service_configuration_conflict"
	}
	if errors.Is(err, errServiceStateUncertain) {
		code = "service_configuration_reconciliation_required"
	}
	writeJSON(w, status, map[string]string{"error": code})
}

func validateServiceStateOptions(directory, shareDirectory string, transport apiTransportConfig) error {
	if directory == "" {
		return nil
	}
	host, _, wildcard, err := parseListenAddress(transport.Address)
	if shareDirectory != "" || err != nil || wildcard || !isLoopbackHost(host) {
		return errors.New("development service state requires one policy authority and a loopback listener")
	}
	return nil
}
