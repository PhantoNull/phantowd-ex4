//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

type qemuNASPolicyHTTP struct {
	server         *httptest.Server
	closeTransport func() error
	exchange       func(context.Context, *naspolicy.Config, int) error
}

// Synthetic session/certificate, actual HTTPS and one retained state authority.
func newQEMUNASPolicyHTTP(state nasStateAuthority) (*qemuNASPolicyHTTP, error) {
	return newQEMUNASPolicyHTTPAt(state, "")
}

func (h *qemuNASPolicyHTTP) Close() error {
	h.server.Close()
	return h.closeTransport()
}

func newQEMUNASPolicyHTTPAt(state nasStateAuthority, path string) (*qemuNASPolicyHTTP, error) {
	s := httptest.NewUnstartedServer(nil)
	origin := "https://" + s.Listener.Addr().String()
	auth := newAuthController(&accountStore{backend: qemuStaticAccount{}}, origin)
	token, session, err := auth.sessions.create(time.Now())
	if err != nil {
		s.Close()
		return nil, err
	}
	handler := http.Handler(newNASStateHandler(auth, state))
	closeTransport := func() error { return nil }
	if path != "" {
		for _, options := range [][2]bool{{true, true}, {false, false}} {
			if _, close, err := openNASPolicyHTTP(auth, path, options[0], options[1]); err == nil {
				close()
				s.Close()
				return nil, errors.New("NAS mixed/plaintext startup accepted")
			}
		}
		handler, closeTransport, err = openNASPolicyHTTP(auth, path, false, true)
		if err != nil {
			s.Close()
			return nil, err
		}
	}
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	s.Config = newConfiguredServer(newHandlerWithNASPolicy(nil, nil, nil, nil, auth, nil, nil, nil, handler), apiTransportConfig{Address: s.Listener.Addr().String(), AllowedOrigin: origin, TLSConfig: s.TLS})
	s.StartTLS()
	client := s.Client()
	client.Timeout = 5 * time.Second
	expected := qemuPersistentNASPolicy(1)
	return &qemuNASPolicyHTTP{server: s, closeTransport: closeTransport, exchange: func(ctx context.Context, next *naspolicy.Config, want int) error {
		var payload bytes.Buffer
		method := http.MethodGet
		if next != nil {
			method = http.MethodPut
			if err := json.NewEncoder(&payload).Encode(next); err != nil {
				return err
			}
		}
		r, err := http.NewRequestWithContext(ctx, method, origin+nasStatePath, &payload)
		if err != nil {
			return err
		}
		r.AddCookie(&http.Cookie{Name: hostCookieName, Value: token})
		r.Header.Set("Origin", origin)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-PhantoWD-CSRF", session.csrf)
		resp, err := client.Do(r)
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(resp.Body, naspolicy.MaxInputBytes+1025))
		if err := errors.Join(readErr, resp.Body.Close()); err != nil {
			return err
		}
		if resp.StatusCode != want || len(data) > naspolicy.MaxInputBytes+1024 || resp.Header.Get("Cache-Control") != "no-store" {
			return errors.New("NAS policy HTTPS response refused")
		}
		if want == 503 || want == 409 {
			code, retry := "nas_configuration_conflict", ""
			if want == 503 {
				code, retry = "nas_configuration_busy", "1"
			}
			if want == 503 && next == nil {
				code, retry = "nas_configuration_unavailable", ""
			}
			var refusal map[string]string
			if resp.Header.Get("Retry-After") != retry || json.Unmarshal(data, &refusal) != nil || len(refusal) != 1 || refusal["error"] != code {
				return errors.New("NAS policy HTTPS did not report the expected refusal")
			}
			return nil
		}
		var reply nasStateResponse
		if json.Unmarshal(data, &reply) != nil || reply.SchemaVersion != 1 || reply.Scope != "stored-desired-nas-policy-only" || reply.Applied || reply.ActivationAvailable {
			return errors.New("NAS policy HTTPS envelope differs")
		}
		if next == nil {
			current := expected
			var err error
			if state != nil {
				current, err = state.Snapshot(ctx)
			}
			if err != nil || reply.Saved || reply.Configuration == nil || !reflect.DeepEqual(*reply.Configuration, current) || reply.Revision != current.Revision {
				return errors.New("NAS policy HTTPS did not read original authority")
			}
		} else if !reply.Saved || reply.Revision != next.Revision || reply.Configuration != nil {
			return errors.New("NAS policy HTTPS commit was not confirmed")
		}
		if next != nil {
			expected = *next
		}
		return nil
	}}, nil
}
