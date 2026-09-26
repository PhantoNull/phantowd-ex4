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
	"sync"
	"time"
)

const (
	authStatusPath    = "/api/v1/auth/status"
	authSetupPath     = "/api/v1/auth/setup"
	authLoginPath     = "/api/v1/auth/login"
	authSessionPath   = "/api/v1/auth/session"
	authLogoutPath    = "/api/v1/auth/logout"
	authLogoutAllPath = "/api/v1/auth/logout-all"
	authPasswordPath  = "/api/v1/auth/password"
	maxAuthBodySize   = 2048
	loginWindow       = time.Minute
	loginMaxAttempts  = 5
)

type authController struct {
	accounts         *accountStore
	sessions         *sessionStore
	allowedOrigin    string
	loginMu          sync.Mutex
	windowAt         time.Time
	attempts         int
	passwordWindowAt time.Time
	passwordAttempts int
	passwordSlot     chan struct{}
}

type authStatus struct {
	SetupRequired bool `json:"setup_required"`
	Authenticated bool `json:"authenticated"`
}

type setupRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func newAuthController(accounts *accountStore, allowedOrigin string) *authController {
	return &authController{accounts: accounts, sessions: newSessionStore(), allowedOrigin: allowedOrigin, passwordSlot: make(chan struct{}, 1)}
}

func (a *authController) isAuthPath(path string) bool {
	switch path {
	case authStatusPath, authSetupPath, authLoginPath, authSessionPath, authLogoutPath, authLogoutAllPath, authPasswordPath:
		return true
	default:
		return false
	}
}

func (a *authController) serve(w http.ResponseWriter, r *http.Request) bool {
	switch r.URL.Path {
	case authStatusPath:
		a.status(w, r)
	case authSetupPath:
		a.setup(w, r)
	case authLoginPath:
		a.login(w, r)
	case authSessionPath:
		a.session(w, r)
	case authLogoutPath:
		a.logout(w, r)
	case authLogoutAllPath:
		a.logoutAll(w, r)
	case authPasswordPath:
		a.changePassword(w, r)
	default:
		return false
	}
	return true
}

func (a *authController) status(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !readRequestHasNoInput(w, r) {
		return
	}
	configured, err := a.accounts.configured()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "account_state_unavailable"})
		return
	}
	_, _, authenticated := a.sessions.sessionFromRequest(r, time.Now())
	writeJSON(w, http.StatusOK, authStatus{SetupRequired: !configured, Authenticated: configured && authenticated})
}

func (a *authController) setup(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) || !validOrigin(r, a.allowedOrigin) {
		if r.Method == http.MethodPost {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
		}
		return
	}
	var request setupRequest
	if !decodeAuthJSON(w, r, &request) {
		return
	}
	epoch := a.sessions.currentEpoch()
	if err := a.accounts.setup(r.Context(), request.Username, request.Password); err != nil {
		switch {
		case errors.Is(err, errAccountConfigured):
			writeJSON(w, http.StatusConflict, map[string]string{"error": "setup_unavailable"})
		case errors.Is(err, errInvalidUsername), errors.Is(err, errShortPassword):
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_setup"})
		default:
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "account_setup_failed"})
		}
		return
	}
	a.issueSession(w, r, http.StatusCreated, epoch)
}

func (a *authController) login(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !validOrigin(r, a.allowedOrigin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
		return
	}
	if !a.allowLogin(time.Now()) {
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "login_rate_limited"})
		return
	}
	var request loginRequest
	if !decodeAuthJSON(w, r, &request) {
		return
	}
	epoch := a.sessions.currentEpoch()
	valid, err := a.accounts.authenticate(r.Context(), request.Username, request.Password)
	if errors.Is(err, errAccountMissing) {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "setup_required"})
		return
	}
	if errors.Is(err, errCredentials) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "authentication_unavailable"})
		return
	}
	if !valid {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_credentials"})
		return
	}
	a.issueSession(w, r, http.StatusOK, epoch)
}

func (a *authController) session(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodGet) || !readRequestHasNoInput(w, r) {
		return
	}
	configured, err := a.accounts.configured()
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "account_state_unavailable"})
		return
	}
	if !configured {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
		return
	}
	_, session, ok := a.sessions.sessionFromRequest(r, time.Now())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"csrf_token": session.csrf, "expires_at": session.expiresAt})
}

func (a *authController) logout(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !validOrigin(r, a.allowedOrigin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
		return
	}
	if !readRequestHasNoInput(w, r) {
		return
	}
	token, session, ok := a.sessions.sessionFromRequest(r, time.Now())
	if !ok {
		clearSessionCookie(w, r)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
		return
	}
	if !validCSRF(session, r.Header.Get("X-PhantoWD-CSRF")) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_validation_failed"})
		return
	}
	a.sessions.revoke(token)
	clearSessionCookie(w, r)
	writeJSON(w, http.StatusOK, map[string]bool{"logged_out": true})
}

func (a *authController) authorize(r *http.Request) bool {
	configured, err := a.accounts.configured()
	if err != nil || !configured {
		return false
	}
	_, _, ok := a.sessions.sessionFromRequest(r, time.Now())
	return ok
}

func (a *authController) validateCSRF(r *http.Request) bool {
	_, session, ok := a.sessions.sessionFromRequest(r, time.Now())
	return ok && validCSRF(session, r.Header.Get("X-PhantoWD-CSRF"))
}

func (a *authController) logoutAll(w http.ResponseWriter, r *http.Request) {
	if !requireMethod(w, r, http.MethodPost) {
		return
	}
	if !validOrigin(r, a.allowedOrigin) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "origin_not_allowed"})
		return
	}
	if !readRequestHasNoInput(w, r) {
		return
	}
	cookies := r.CookiesNamed(cookieName(r))
	if len(cookies) != 1 {
		clearSessionCookie(w, r)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
		return
	}
	if len(r.Header.Values("X-PhantoWD-CSRF")) != 1 {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_validation_failed"})
		return
	}
	err := a.sessions.revokeAll(cookies[0].Value, r.Header.Get("X-PhantoWD-CSRF"), time.Now())
	if errors.Is(err, errSessionCSRF) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "csrf_validation_failed"})
		return
	}
	clearSessionCookie(w, r)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication_required"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"all_panel_sessions_revoked": true})
}

func (a *authController) issueSession(w http.ResponseWriter, r *http.Request, status int, epoch *sessionEpoch) {
	err := a.accounts.withConfigured(func() error {
		if token, _, ok := a.sessions.sessionFromRequest(r, time.Now()); ok {
			a.sessions.revoke(token)
		}
		token, _, err := a.sessions.createForEpoch(time.Now(), epoch)
		if err != nil {
			return err
		}
		a.sessions.setCookie(w, r, token)
		return nil
	})
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "session_unavailable"})
		return
	}
	writeJSON(w, status, map[string]bool{"authenticated": true})
}

func (a *authController) allowLogin(now time.Time) bool {
	a.loginMu.Lock()
	defer a.loginMu.Unlock()
	if a.windowAt.IsZero() || now.Sub(a.windowAt) >= loginWindow || now.Before(a.windowAt) {
		a.windowAt = now
		a.attempts = 0
	}
	if a.attempts >= loginMaxAttempts {
		return false
	}
	a.attempts++
	return true
}

func requireMethod(w http.ResponseWriter, r *http.Request, method string) bool {
	if r.Method == method {
		return true
	}
	w.Header().Set("Allow", method)
	writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method_not_allowed"})
	return false
}

func readRequestHasNoInput(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unexpected_input"})
		return false
	}
	return true
}

func decodeAuthJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	contentTypes := r.Header.Values("Content-Type")
	if len(contentTypes) != 1 || r.Header.Get("Content-Encoding") != "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return false
	}
	mediaType, _, err := mime.ParseMediaType(contentTypes[0])
	if err != nil || mediaType != "application/json" || r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength > maxAuthBodySize {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return false
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxAuthBodySize))
	if err != nil || rejectDuplicateJSONKeys(data) != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return false
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return false
	}
	return true
}

func rejectDuplicateJSONKeys(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("trailing JSON value")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("invalid JSON object key")
			}
			if _, exists := seen[key]; exists {
				return errors.New("duplicate JSON object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return errors.New("unterminated JSON object")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return errors.New("unterminated JSON array")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}
