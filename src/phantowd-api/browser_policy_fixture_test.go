// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Test-binary-only desired policy. Nothing survives process exit, no appliance
// storage/backend is opened, and no service/account/disk activation is possible.
func newBrowserServicePolicyBackend() *serviceStateBackend {
	var mutex sync.Mutex
	var stored []byte
	var revision uint64
	return &serviceStateBackend{
		load: func() (*fileservice.Config, error) {
			mutex.Lock()
			defer mutex.Unlock()
			if stored == nil {
				return nil, nil
			}
			c, err := fileservice.DecodeConfig(bytes.NewReader(stored))
			if err != nil {
				return nil, err
			}
			return &c, nil
		},
		commit: func(expected uint64, c fileservice.Config) error {
			mutex.Lock()
			defer mutex.Unlock()
			if expected != revision {
				return errServiceStateConflict
			}
			if expected == ^uint64(0) || c.Revision != expected+1 || c.Validate() != nil {
				return fileservice.ErrConfig
			}
			if stored != nil {
				current, err := fileservice.DecodeConfig(bytes.NewReader(stored))
				if err != nil {
					return err
				}
				if fileservice.ValidateRetainedNFSBindings(current, c) != nil {
					return errServiceStateRejected
				}
			}
			data, err := json.Marshal(c)
			if err != nil {
				return err
			}
			// Same bounded codec as the handler; no caller-owned slices survive.
			if _, err := fileservice.DecodeConfig(bytes.NewReader(data)); err != nil {
				return err
			}
			stored = data
			revision = c.Revision
			return nil
		},
	}
}

func TestBrowserPolicyFixtureActualHTTPRoundTrip(t *testing.T) {
	handler, accounts := newBrowserFixtureHandlerWithServiceState(defaultPublicOrigin, newBrowserServicePolicyBackend())
	defer accounts.Close()
	setup := httptest.NewRecorder()
	r := loopbackRequest("POST", authSetupPath, strings.NewReader(`{"username":"browser-admin","password":"browser fixture original passphrase"}`))
	r.Header.Set("Origin", defaultPublicOrigin)
	r.Header.Set("Content-Type", "application/json")
	handler.ServeHTTP(setup, r)
	if setup.Code != http.StatusCreated || len(setup.Result().Cookies()) != 1 {
		t.Fatal("fixture setup failed")
	}
	cookie := setup.Result().Cookies()[0]
	request := func(method, path, body, csrf string) *httptest.ResponseRecorder {
		r := loopbackRequest(method, path, strings.NewReader(body))
		r.AddCookie(cookie)
		r.Header.Set("Origin", defaultPublicOrigin)
		if method != "GET" {
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("X-PhantoWD-CSRF", csrf)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	initial := request("GET", serviceStatePath, "", "")
	var state serviceStateResponse
	if initial.Code != 200 || json.Unmarshal(initial.Body.Bytes(), &state) != nil || state.Initialized || state.Configuration != nil {
		t.Fatal("fixture did not start uninitialized")
	}
	session := request("GET", "/api/v1/auth/session", "", "")
	var token struct {
		CSRF string `json:"csrf_token"`
	}
	if session.Code != 200 || json.Unmarshal(session.Body.Bytes(), &token) != nil || token.CSRF == "" {
		t.Fatal("fixture session unavailable")
	}
	for revision := uint64(1); revision <= 2; revision++ {
		data, err := json.Marshal(serviceConfigFixture(revision))
		if err != nil {
			t.Fatal(err)
		}
		saved := request("PUT", serviceStatePath, string(data), token.CSRF)
		var receipt struct {
			Saved               bool   `json:"saved"`
			Applied             bool   `json:"applied"`
			ActivationAvailable bool   `json:"activation_available"`
			Revision            uint64 `json:"revision"`
		}
		if saved.Code != 200 || json.Unmarshal(saved.Body.Bytes(), &receipt) != nil || !receipt.Saved || receipt.Applied || receipt.ActivationAvailable || receipt.Revision != revision {
			t.Fatal("fixture save did not remain desired-state only")
		}
		read := request("GET", serviceStatePath, "", "")
		if read.Code != 200 || json.Unmarshal(read.Body.Bytes(), &state) != nil || !state.Initialized || state.Configuration == nil || state.Configuration.Revision != revision {
			t.Fatal("fixture did not reread saved revision")
		}
		if stale := request("PUT", serviceStatePath, string(data), token.CSRF); stale.Code != 409 {
			t.Fatal("fixture accepted a stale revision")
		}
	}
	base := serviceConfigFixture(3)
	base.Shares.Volumes = []shareconfig.Volume{{ID: "bulk", FilesystemUUID: "11111111-2222-4333-8444-555555555555"}}
	base.NFS.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
		Clients: []nfsconfig.Client{{Network: "192.0.2.1/32", Access: "ro", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
	data, err := json.Marshal(base)
	if err != nil || base.Validate() != nil {
		t.Fatal("invalid browser fixture policy", err)
	}
	if reply := request("PUT", serviceStatePath, string(data), token.CSRF); reply.Code != 200 {
		t.Fatal("fixture NFS seed failed", reply.Code)
	}
	before := request("GET", serviceStatePath, "", "").Body.String()
	base.Revision, base.Shares.Revision, base.NFS.Revision, base.NFS.VolumeRevision = 4, 4, 4, 4
	base.NFS.Exports[0].RelativePath = "unrelated-root"
	data, err = json.Marshal(base)
	if err != nil {
		t.Fatal(err)
	}
	if reply := request("PUT", serviceStatePath, string(data), token.CSRF); reply.Code != 422 || reply.Body.String() != "{\"error\":\"invalid_service_configuration\"}\n" {
		t.Fatal("browser fixture accepted retained export rebinding", reply.Code, reply.Body.String())
	}
	if after := request("GET", serviceStatePath, "", ""); after.Code != 200 || after.Body.String() != before {
		t.Fatal("rejected browser save changed policy")
	}
}
