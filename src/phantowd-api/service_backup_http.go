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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
)

const (
	serviceBackupPath             = "/api/v1/file-services/backup"
	serviceRestorePreviewPath     = "/api/v1/file-services/restore-preview"
	serviceExpectedRevisionHeader = "X-PhantoWD-Expected-Revision"
)

// All three routes use the SAME handler/gate and fixed startup-bound backend.
// Uploaded backups are never normalized in the browser before strict decoding.
func serviceBackupOperation(w http.ResponseWriter, r *http.Request, auth *authController, backend *serviceStateBackend) {
	var candidate fileservice.Config
	var expected uint64
	if r.URL.Path == serviceRestorePreviewPath {
		values := r.Header.Values(serviceExpectedRevisionHeader)
		if len(values) != 1 {
			writeJSON(w, 400, map[string]string{"error": "invalid_backup_request"})
			return
		}
		var err error
		expected, err = strconv.ParseUint(values[0], 10, 64)
		if err != nil || strconv.FormatUint(expected, 10) != values[0] {
			writeJSON(w, 400, map[string]string{"error": "invalid_backup_request"})
			return
		}
		data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, fileservice.MaxBackupBytes))
		if err != nil {
			status := http.StatusBadRequest
			var large *http.MaxBytesError
			if errors.As(err, &large) {
				status = http.StatusRequestEntityTooLarge
			}
			writeJSON(w, status, map[string]string{"error": "invalid_backup_request"})
			return
		}
		candidate, err = fileservice.RestoreCandidate(data, expected)
		if err != nil {
			writeJSON(w, 422, map[string]string{"error": "invalid_file_service_backup"})
			return
		}
	}
	if !serviceBackupSessionCurrent(w, r, auth) {
		return
	}
	c, err := loadValidatedServiceConfiguration(backend)
	if err != nil {
		serviceStateError(w, err)
		return
	}
	if !serviceBackupSessionCurrent(w, r, auth) {
		return
	}
	if r.URL.Path == serviceBackupPath {
		if c == nil {
			writeJSON(w, 409, map[string]string{"error": "service_configuration_not_initialized"})
			return
		}
		data, err := fileservice.EncodeBackup(*c)
		if err != nil {
			serviceStateError(w, err)
			return
		}
		if !serviceBackupSessionCurrent(w, r, auth) {
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="phantowd-file-services.json"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(data)
		return
	}
	current := uint64(0)
	if c != nil {
		current = c.Revision
	}
	if current != expected {
		serviceStateError(w, errServiceStateConflict)
		return
	}
	preview, err := fileservice.Build(candidate.Shares, candidate.NFS)
	if err != nil {
		writeJSON(w, 422, map[string]string{"error": "invalid_file_service_backup"})
		return
	}
	if !serviceBackupSessionCurrent(w, r, auth) {
		return
	}
	writeJSON(w, 200, struct {
		SchemaVersion       int                 `json:"schema_version"`
		Scope               string              `json:"scope"`
		ExpectedRevision    uint64              `json:"expected_revision"`
		Configuration       fileservice.Config  `json:"configuration"`
		Preview             fileservice.Preview `json:"preview"`
		Saved               bool                `json:"saved"`
		Applied             bool                `json:"applied"`
		RuntimeValidated    bool                `json:"runtime_validated"`
		ActivationAvailable bool                `json:"activation_available"`
	}{SchemaVersion: 1, Scope: "file-service-restore-preview-only", ExpectedRevision: expected, Configuration: candidate, Preview: preview})
}

func serviceBackupSessionCurrent(w http.ResponseWriter, r *http.Request, auth *authController) bool {
	if r.Context().Err() != nil {
		writeJSON(w, 400, map[string]string{"error": "request_cancelled"})
		return false
	}
	if !auth.authorize(r) || (r.Method == http.MethodPost && !auth.validateCSRF(r)) {
		writeJSON(w, 401, map[string]string{"error": "authentication_required"})
		return false
	}
	return true
}

func loadValidatedServiceConfiguration(backend *serviceStateBackend) (*fileservice.Config, error) {
	c, err := backend.load()
	if err != nil || c == nil {
		return c, err
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	data, err := json.Marshal(c)
	if err != nil {
		return nil, err
	}
	validated, err := fileservice.DecodeConfig(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	return &validated, nil
}
