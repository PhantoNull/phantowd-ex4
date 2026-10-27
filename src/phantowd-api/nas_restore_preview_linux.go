//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Runs behind the NAS handler's original authority, session and request gate.
// Candidate JSON is a string so a browser need not round/re-encode uint64 fields.
func serveNASRestorePreview(w http.ResponseWriter, r *http.Request, auth *authController, state nasStateAuthority) {
	values := r.Header.Values(serviceExpectedRevisionHeader)
	expected, err := strconv.ParseUint(r.Header.Get(serviceExpectedRevisionHeader), 10, 64)
	if err != nil || len(values) != 1 || strconv.FormatUint(expected, 10) != values[0] {
		writeJSON(w, 400, map[string]string{"error": "invalid_backup_request"})
		return
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, naspolicy.MaxBackupBytes))
	if err != nil {
		status := 400
		var large *http.MaxBytesError
		if errors.As(err, &large) {
			status = 413
		}
		writeJSON(w, status, map[string]string{"error": "invalid_backup_request"})
		return
	}
	candidate, err := naspolicy.RestoreCandidate(data, expected)
	if err != nil {
		writeJSON(w, 422, map[string]string{"error": "invalid_nas_policy_backup"})
		return
	}
	if !serviceBackupSessionCurrent(w, r, auth) {
		return
	}
	current, err := state.Snapshot(r.Context())
	if err != nil || current.Validate() != nil {
		if err == nil {
			err = naspolicystore.ErrInvalid
		}
		nasStateError(w, err)
		return
	}
	if !serviceBackupSessionCurrent(w, r, auth) {
		return
	}
	if current.Revision != expected {
		nasStateError(w, naspolicystore.ErrConflict)
		return
	}
	if fileservice.ValidateRetainedNFSBindings(current.FileServices, candidate.FileServices) != nil {
		writeJSON(w, 422, map[string]string{"error": "invalid_nas_policy_backup"})
		return
	}
	wire, err := json.Marshal(candidate)
	if err != nil {
		nasStateError(w, naspolicystore.ErrInvalid)
		return
	}
	matches := naspolicy.SameDefinitions(current, candidate)
	if serviceBackupSessionCurrent(w, r, auth) {
		writeJSON(w, 200, map[string]any{"schema_version": 1, "scope": "nas-policy-restore-preview-only",
			"expected_revision": expected, "candidate_json": string(wire), "matches_current": matches, "saved": false, "applied": false,
			"runtime_validated": false, "activation_available": false})
	}
}
