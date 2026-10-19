//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strconv"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
)

// Actual loopback HTTP(S), actual configuration backend, synthetic session.
// Login and certificate provisioning are covered elsewhere, not by this test.
func exerciseQEMUServiceHTTP(directory string, expected, next uint64, secure bool) error {
	backend, closeState, err := openDevelopmentServiceState(directory)
	if err != nil {
		return err
	}
	defer closeState()
	srv := httptest.NewUnstartedServer(nil)
	defer srv.Close()
	scheme := "http"
	sessionName := sessionCookieName
	if secure {
		scheme = "https"
		sessionName = hostCookieName
		srv.TLS = &tls.Config{MinVersion: tls.VersionTLS12}
	}
	origin := scheme + "://" + srv.Listener.Addr().String()
	auth := newAuthController(&accountStore{backend: qemuStaticAccount{}}, origin)
	token, session, err := auth.sessions.create(time.Now())
	if err != nil {
		return err
	}
	srv.Config = newConfiguredServer(newHandlerWithServiceState(nil, nil, nil, nil, auth, nil, backend), apiTransportConfig{Address: srv.Listener.Addr().String(), AllowedOrigin: origin, TLSConfig: srv.TLS})
	if secure {
		srv.StartTLS()
	} else {
		srv.Start()
	}
	client := srv.Client()
	client.Timeout = 5 * time.Second
	requestAt := func(method, path string, data []byte, authenticated, csrf bool, expectedRevision *uint64) (int, []byte, error) {
		r, err := http.NewRequest(method, origin+path, bytes.NewReader(data))
		if err != nil {
			return 0, nil, err
		}
		if authenticated {
			r.AddCookie(&http.Cookie{Name: sessionName, Value: token})
		}
		if method != http.MethodGet {
			r.Header.Set("Origin", origin)
			r.Header.Set("Content-Type", "application/json")
			if csrf {
				r.Header.Set("X-PhantoWD-CSRF", session.csrf)
			}
		}
		if expectedRevision != nil {
			r.Header.Set(serviceExpectedRevisionHeader, strconv.FormatUint(*expectedRevision, 10))
		}
		resp, err := client.Do(r)
		if err != nil {
			return 0, nil, err
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.Header.Get("Cache-Control") != "no-store" {
			return 0, nil, errors.New("service policy cached")
		}
		return resp.StatusCode, body, err
	}
	request := func(method string, data []byte, authenticated, csrf bool) (int, []byte, error) {
		return requestAt(method, serviceStatePath, data, authenticated, csrf, nil)
	}
	checkRead := func(revision uint64) error {
		status, body, err := request(http.MethodGet, nil, true, false)
		var response serviceStateResponse
		if err != nil || status != 200 || json.Unmarshal(body, &response) != nil || response.Applied || response.RuntimeValidated || response.ActivationAvailable || response.Scope != "development-stored-file-service-policy-only" {
			return fmt.Errorf("invalid %s service read: status=%d transport_error=%v", scheme, status, err)
		}
		if revision == 0 {
			if response.Initialized || response.Configuration != nil {
				return errors.New("uninitialized became empty")
			}
			return nil
		}
		if !response.Initialized || response.Configuration == nil || !reflect.DeepEqual(*response.Configuration, qemuPersistentServices(revision)) {
			return errors.New("wire service policy mismatch")
		}
		return nil
	}
	if err := checkRead(expected); err != nil {
		return err
	}
	// A TLS request must not accept the unprotected HTTP cookie name.
	if secure {
		sessionName = sessionCookieName
		status, _, err := request(http.MethodGet, nil, true, false)
		sessionName = hostCookieName
		if err != nil || status != http.StatusUnauthorized {
			return errors.New("HTTPS accepted HTTP session cookie")
		}
	}
	backup, err := fileservice.EncodeBackup(qemuPersistentServices(next))
	if err != nil {
		return err
	}
	status, body, err := requestAt(http.MethodPost, serviceRestorePreviewPath, backup, true, true, &expected)
	var restore struct {
		Configuration    fileservice.Config  `json:"configuration"`
		ExpectedRevision uint64              `json:"expected_revision"`
		Preview          fileservice.Preview `json:"preview"`
		Saved            bool                `json:"saved"`
		Applied          bool                `json:"applied"`
	}
	if err != nil || status != 200 || json.Unmarshal(body, &restore) != nil || restore.ExpectedRevision != expected ||
		!reflect.DeepEqual(restore.Configuration, qemuPersistentServices(next)) || restore.Saved || restore.Applied ||
		restore.Preview.Persisted || restore.Preview.Applied || restore.Preview.RuntimeValidated || restore.Preview.ActivationAvailable {
		return errors.New("wire backup restore preview invalid")
	}
	if err := checkRead(expected); err != nil {
		return errors.New("wire restore preview changed saved state")
	}
	data, err := json.Marshal(restore.Configuration)
	if err != nil {
		return err
	}
	for _, spec := range []struct {
		auth, csrf bool
		status     int
	}{{false, false, 401}, {true, false, 403}, {true, true, 200}, {true, true, 409}} {
		status, body, err := request(http.MethodPut, data, spec.auth, spec.csrf)
		if err != nil || status != spec.status {
			return errors.New("wire service write boundary failed")
		}
		if status == 200 {
			var reply struct {
				Revision            uint64 `json:"revision"`
				Saved               bool   `json:"saved"`
				Applied             bool   `json:"applied"`
				RuntimeValidated    bool   `json:"runtime_validated"`
				ActivationAvailable bool   `json:"activation_available"`
			}
			if json.Unmarshal(body, &reply) != nil || !reply.Saved || reply.Revision != next || reply.Applied || reply.RuntimeValidated || reply.ActivationAvailable {
				return errors.New("wire save authority boundary")
			}
		}
	}
	if err := checkRead(next); err != nil {
		return err
	}
	// A retained export ID cannot silently acquire a different source. This
	// must be a known, pre-effect refusal on both transports and both boots,
	// leaving the saved revision available without recovery or retry.
	rebound := qemuPersistentServices(next + 1)
	rebound.NFS.Exports[0].RelativePath = "unrelated-root"
	reboundData, err := json.Marshal(rebound)
	if err != nil {
		return err
	}
	status, body, err = request(http.MethodPut, reboundData, true, true)
	if err != nil || status != http.StatusUnprocessableEntity || string(body) != "{\"error\":\"invalid_service_configuration\"}\n" {
		return errors.New("wire retained export binding refusal unavailable")
	}
	if err := checkRead(next); err != nil {
		return errors.New("wire rejected save changed current policy")
	}
	status, body, err = requestAt(http.MethodGet, serviceBackupPath, nil, true, false, nil)
	if err != nil || status != 200 || !bytes.Equal(body, backup) {
		return errors.New("wire backup does not match saved policy")
	}
	status, _, err = requestAt(http.MethodPost, serviceRestorePreviewPath, backup, true, true, &expected)
	if err != nil || status != http.StatusConflict {
		return errors.New("wire stale restore preview accepted")
	}
	srv.Close()
	if err := closeState(); err != nil {
		return err
	}
	reopened, closeAgain, err := openDevelopmentServiceState(directory)
	if err != nil {
		return err
	}
	defer closeAgain()
	got, err := reopened.load()
	if err != nil || got == nil || !reflect.DeepEqual(*got, qemuPersistentServices(next)) {
		return errors.New("wire commit did not reopen")
	}
	return nil
}

func exerciseQEMUServiceHTTPPersistence(root, phase string) error {
	dir := root + "/services-http"
	start := uint64(0)
	if phase == "seed" {
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
	} else if phase == "verify" {
		start = 2
	} else {
		return errors.New("invalid HTTP state phase")
	}
	if err := exerciseQEMUServiceHTTP(dir, start, start+1, false); err != nil {
		return err
	}
	if err := exerciseQEMUServiceHTTP(dir, start+1, start+2, true); err != nil {
		return err
	}
	if phase == "verify" {
		fmt.Println("PHANTOWD_SERVICE_HTTP_READY protocols=http,https authenticated=true csrf=true stale_write_denied=true rejected_write=true after_reboot=true activation=false scope=disposable-qemu-only")
	}
	return nil
}
