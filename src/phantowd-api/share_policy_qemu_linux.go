//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"reflect"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Real handler dispatch with a synthetic pre-authenticated session and actual
// store adapter after the second boot. No listener or default account. Login
// and TLS wire behavior is exercised separately by the existing smoke.
func exerciseQEMUSharePolicyHTTP(directory string, expected shareconfig.Config) error {
	load, closeReader, err := openSharePolicyReader(directory)
	if err != nil {
		return err
	}
	defer closeReader()
	accounts := &accountStore{backend: qemuStaticAccount{}}
	auth := newAuthController(accounts, defaultPublicOrigin)
	token, _, err := auth.sessions.create(time.Now())
	if err != nil {
		return err
	}
	h := newHandlerWithSharePolicy(nil, nil, nil, nil, auth, load)
	for _, authenticated := range []bool{false, true} {
		r := httptest.NewRequest(http.MethodGet, defaultPublicOrigin+sharePolicyPath, nil)
		if authenticated {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if !authenticated {
			if w.Code != http.StatusUnauthorized {
				return errors.New("stored share policy exposed without session")
			}
			continue
		}
		var response sharePolicyResponse
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &response) != nil ||
			!response.Initialized || response.Configuration == nil || !reflect.DeepEqual(*response.Configuration, expected) ||
			response.RuntimeValidated || response.ActivationAvailable || response.Scope != "stored-desired-share-policy-only" {
			return errors.New("stored share HTTP policy mismatch")
		}
	}
	fmt.Println("PHANTOWD_SHARE_READ_READY authenticated=true backend=sharestore after_reboot=true mutation=false scope=qemu-handler-dispatch-only")
	return nil
}
