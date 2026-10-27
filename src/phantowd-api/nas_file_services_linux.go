//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

// Called only behind the NAS handler's shared authentication and admission gate.
// This is a view of its retained authority, never an independent policy store.
func serveNASFileServices(w http.ResponseWriter, r *http.Request, auth *authController, state nasStateAuthority) {
	var next fileservice.Config
	var expected uint64
	restore := r.URL.Path == serviceRestorePreviewPath
	if r.Method != http.MethodGet {
		limit := int64(fileservice.MaxConfigBytes)
		if restore {
			limit = fileservice.MaxBackupBytes
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, limit))
		if err != nil {
			status := 400
			var large *http.MaxBytesError
			if errors.As(err, &large) {
				status = 413
			}
			writeJSON(w, status, map[string]string{"error": "invalid_service_configuration_request"})
			return
		}
		if restore {
			values := r.Header.Values(serviceExpectedRevisionHeader)
			expected, err = strconv.ParseUint(r.Header.Get(serviceExpectedRevisionHeader), 10, 64)
			if err != nil || len(values) != 1 || strconv.FormatUint(expected, 10) != values[0] {
				writeJSON(w, 400, map[string]string{"error": "invalid_backup_request"})
				return
			}
			next, err = fileservice.RestoreCandidate(data, expected)
		} else {
			next, err = fileservice.DecodeConfig(bytes.NewReader(data))
			expected = next.Revision - 1
		}
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": "invalid_service_configuration"})
			return
		}
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
	if r.Method == http.MethodGet {
		if r.URL.Path == serviceBackupPath {
			w.Header().Set("Content-Disposition", `attachment; filename="phantowd-file-services.json"`)
			writeJSON(w, 200, fileservice.Backup{Format: fileservice.BackupFormat, SchemaVersion: 1, Configuration: current.FileServices})
			return
		}
		writeJSON(w, 200, serviceStateResponse{SchemaVersion: 1, Scope: "development-stored-file-service-policy-only", Initialized: true, Configuration: &current.FileServices})
		return
	}
	if current.Revision != expected {
		nasStateError(w, naspolicystore.ErrConflict)
		return
	}
	candidate, err := naspolicy.ReplaceFileServices(current, next)
	if err != nil {
		writeJSON(w, 422, map[string]string{"error": "invalid_service_configuration"})
		return
	}
	if !serviceBackupSessionCurrent(w, r, auth) {
		return
	}
	if restore {
		preview, err := fileservice.Build(candidate.FileServices.Shares, candidate.FileServices.NFS)
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": "invalid_file_service_backup"})
			return
		}
		if serviceBackupSessionCurrent(w, r, auth) {
			writeJSON(w, 200, map[string]any{"schema_version": 1, "scope": "file-service-restore-preview-only", "expected_revision": expected,
				"configuration": next, "preview": preview, "saved": false, "applied": false, "runtime_validated": false, "activation_available": false})
		}
		return
	}
	if err := state.Commit(r.Context(), current.Revision, candidate); err != nil {
		nasStateError(w, err)
		return
	}
	writeJSON(w, 200, map[string]any{"schema_version": 1, "scope": "development-stored-file-service-policy-only", "revision": candidate.Revision,
		"saved": true, "applied": false, "runtime_validated": false, "activation_available": false})
}
