// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net/http"
	"sync"
	"time"
)

const (
	sessionCookieName = "phantowd_session"
	hostCookieName    = "__Host-phantowd_session"
	sessionLifetime   = 30 * time.Minute
	maximumSessions   = 8
)

var errSessionCapacity = errors.New("session capacity reached")

type authSession struct {
	csrf      string
	expiresAt time.Time
}

type sessionStore struct {
	mu       sync.Mutex
	sessions map[[sha256.Size]byte]authSession
}

func newSessionStore() *sessionStore {
	return &sessionStore{sessions: make(map[[sha256.Size]byte]authSession)}
}

func (s *sessionStore) create(now time.Time) (string, authSession, error) {
	var tokenBytes, csrfBytes [32]byte
	if _, err := rand.Read(tokenBytes[:]); err != nil {
		return "", authSession{}, errors.New("secure session randomness unavailable")
	}
	if _, err := rand.Read(csrfBytes[:]); err != nil {
		return "", authSession{}, errors.New("secure CSRF randomness unavailable")
	}
	token := base64.RawURLEncoding.EncodeToString(tokenBytes[:])
	session := authSession{
		csrf:      base64.RawURLEncoding.EncodeToString(csrfBytes[:]),
		expiresAt: now.Add(sessionLifetime),
	}
	key := sha256.Sum256(tokenBytes[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	for id, current := range s.sessions {
		if !now.Before(current.expiresAt) {
			delete(s.sessions, id)
		}
	}
	if len(s.sessions) >= maximumSessions {
		return "", authSession{}, errSessionCapacity
	}
	s.sessions[key] = session
	return token, session, nil
}

func (s *sessionStore) find(token string, now time.Time) (authSession, bool) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(tokenBytes) != 32 {
		return authSession{}, false
	}
	key := sha256.Sum256(tokenBytes)
	s.mu.Lock()
	defer s.mu.Unlock()
	session, ok := s.sessions[key]
	if !ok {
		return authSession{}, false
	}
	if !now.Before(session.expiresAt) {
		delete(s.sessions, key)
		return authSession{}, false
	}
	return session, true
}

func (s *sessionStore) revoke(token string) {
	tokenBytes, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(tokenBytes) != 32 {
		return
	}
	key := sha256.Sum256(tokenBytes)
	s.mu.Lock()
	delete(s.sessions, key)
	s.mu.Unlock()
}

func (s *sessionStore) sessionFromRequest(r *http.Request, now time.Time) (string, authSession, bool) {
	cookie, err := r.Cookie(cookieName(r))
	if err != nil {
		return "", authSession{}, false
	}
	session, ok := s.find(cookie.Value, now)
	return cookie.Value, session, ok
}

func (s *sessionStore) setCookie(w http.ResponseWriter, r *http.Request, token string) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(r), Value: token, Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode,
	})
}

func clearSessionCookie(w http.ResponseWriter, r *http.Request) {
	http.SetCookie(w, &http.Cookie{
		Name: cookieName(r), Value: "", Path: "/", HttpOnly: true,
		Secure: r.TLS != nil, SameSite: http.SameSiteStrictMode, MaxAge: -1,
	})
}

func cookieName(r *http.Request) string {
	if r.TLS != nil {
		return hostCookieName
	}
	return sessionCookieName
}

func validCSRF(session authSession, supplied string) bool {
	if len(supplied) != len(session.csrf) {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(session.csrf), []byte(supplied)) == 1
}
