//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
)

// The endpoint only renders this synthetic proposal with the existing test
// session. It has no service operations or caller-supplied fixture paths.
const qemuFileServicePreviewFixture = `{"shares":{"format":"phantowd-share-config","schema_version":1,"revision":1,
"volumes":[{"id":"bulk","filesystem_uuid":"11111111-2222-3333-4444-555555555555"}],
"users":[{"id":"writer","name":"alice"}],
"shares":[{"id":"books","name":"Books","volume_id":"bulk","relative_path":"books","grants":[{"user_id":"writer","access":"rw"}]}]},
"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":1,"volume_revision":1,
"exports":[{"id":"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee","volume_id":"bulk","relative_path":"books",
"clients":[{"network":"127.0.0.1/32","access":"rw","squash":"all","anonymous_uid":101000,"anonymous_gid":101000,"security":"sys"}]}]}}`

func exerciseQEMUFileServicePreview(client *http.Client, origin string) error {
	response, err := client.Get(origin + authSessionPath)
	if err != nil {
		return errors.New("preview session request failed")
	}
	data, err := readSelfTestResponse(response, 4096)
	var session struct {
		CSRFToken string `json:"csrf_token"`
	}
	if err != nil || response.StatusCode != http.StatusOK || json.Unmarshal(data, &session) != nil || session.CSRFToken == "" {
		return errors.New("preview session unavailable")
	}
	for _, spec := range []struct {
		origin, csrf, body string
		status             int
	}{
		{origin, session.CSRFToken, qemuFileServicePreviewFixture, http.StatusOK},
		{origin, "", qemuFileServicePreviewFixture, http.StatusForbidden},
		{"https://attacker.invalid", session.CSRFToken, qemuFileServicePreviewFixture, http.StatusForbidden},
		{origin, session.CSRFToken, strings.Replace(qemuFileServicePreviewFixture, `"volume_revision":1`, `"volume_revision":2`, 1), http.StatusUnprocessableEntity},
	} {
		request, err := http.NewRequest(http.MethodPost, origin+fileServicePreviewPath, strings.NewReader(spec.body))
		if err != nil {
			return err
		}
		request.Header.Set("Origin", spec.origin)
		request.Header.Set("Content-Type", "application/json")
		if spec.csrf != "" {
			request.Header.Set("X-PhantoWD-CSRF", spec.csrf)
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("file-service preview request failed")
		}
		data, err := readSelfTestResponse(response, 16384)
		if err != nil || response.StatusCode != spec.status {
			return errors.New("file-service preview HTTP contract failed")
		}
		if spec.status == http.StatusOK {
			var p fileservice.Preview
			if json.Unmarshal(data, &p) != nil || p.SchemaVersion != 1 || p.Scope != "desired-policy-only" || p.Persisted || p.Applied || p.RuntimeValidated || p.ActivationAvailable ||
				len(p.Samba.Shares) != 1 || len(p.NFS.Exports) != 1 || p.Samba.Shares[0].Path != p.NFS.Exports[0].Path || !p.NFS.UsesAUTH_SYS ||
				!strings.Contains(p.Samba.Sections, "write list = alice") || !strings.Contains(p.NFS.Table, "anonuid=101000,anongid=101000") {
				return errors.New("file-service preview lost policy or overstated activation")
			}
		}
	}
	return nil
}
