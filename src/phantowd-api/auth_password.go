// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"mime"
	"net/http"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
)

// Includes worst-case JSON escaping for two 1024-byte passwords. Never log the
// body, and never accept credential replacement in a GET/query-string route.
const maxPasswordChangeBody = 16 * 1024

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (a *authController) changePassword(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !validOrigin(r, a.allowedOrigin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
		return
	}
	cookies := r.CookiesNamed(cookieName(r))
	if len(cookies) != 1 {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
		return
	}
	token := cookies[0].Value
	session, ok := a.sessions.find(token, time.Now())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
		return
	}
	if len(r.Header.Values("X-PhantoWD-CSRF")) != 1 || !validCSRF(session, r.Header.Get("X-PhantoWD-CSRF")) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_validation_failed"})
		return
	}
	configured, err := a.accounts.configured()
	if err != nil || !configured {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "account_state_unavailable"})
		return
	}
	var request passwordChangeRequest
	if !decodePasswordChange(w, r, &request) {
		return
	}
	// Do not queue multiple expensive password transactions behind the KDF.
	select {
	case a.passwordSlot <- struct{}{}:
		defer func() { <-a.passwordSlot }()
	default:
		w.Header().Set("Retry-After", "1")
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "password_change_busy"})
		return
	}
	if !a.allowPasswordChange(time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "password_change_rate_limited"})
		return
	}
	revoked := false
	err = a.accounts.changePassword(r.Context(), request.CurrentPassword, request.NewPassword, func() error {
		// Recheck the SAME session/CSRF after KDF work, atomically with global
		// revocation. Concurrent logout/expiry cannot authorize a later commit.
		err := a.sessions.revokeAll(token, r.Header.Get("X-PhantoWD-CSRF"), time.Now())
		revoked = err == nil
		return err
	})
	if revoked {
		clearSessionCookie(w, r)
	}
	if err != nil {
		status, code := http.StatusServiceUnavailable, "password_change_unavailable"
		switch {
		case errors.Is(err, errCredentials):
			status, code = http.StatusUnauthorized, "current_password_invalid"
		case errors.Is(err, errShortPassword), errors.Is(err, errPasswordUnchanged):
			status, code = http.StatusUnprocessableEntity, "new_password_invalid"
		case errors.Is(err, errAccountConflict):
			status, code = http.StatusConflict, "credential_revision_conflict"
		case errors.Is(err, errSessionMissing):
			status, code = http.StatusUnauthorized, "authentication_required"
		case errors.Is(err, errSessionCSRF):
			status, code = http.StatusForbidden, "csrf_validation_failed"
		case errors.Is(err, errAccountUncertain):
			code = "password_change_reconciliation_required"
		}
		writeJSON(w, status, map[string]string{"error": code})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"password_changed": true, "reauthentication_required": true, "all_panel_sessions_revoked": true})
}

func decodePasswordChange(w http.ResponseWriter, r *http.Request, request *passwordChangeRequest) bool {
	invalid := func() bool {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return false
	}
	if len(r.Header.Values("Content-Type")) != 1 || len(r.Header.Values("Content-Encoding")) != 0 ||
		r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > maxPasswordChangeBody {
		return invalid()
	}
	media, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) > 1 ||
		(len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		return invalid()
	}
	if configjson.Decode(http.MaxBytesReader(w, r.Body, maxPasswordChangeBody), request, maxPasswordChangeBody, 1,
		map[string]bool{"current_password": true, "new_password": true}) != nil {
		return invalid()
	}
	return true
}

func (a *authController) allowPasswordChange(now time.Time) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	if a.passwordWindowAt.IsZero() || now.Sub(a.passwordWindowAt) >= loginWindow || now.Before(a.passwordWindowAt) {
		a.passwordWindowAt, a.passwordAttempts = now, 0
	}
	if a.passwordAttempts >= loginMaxAttempts {
		return false
	}
	a.passwordAttempts++
	return true
}
