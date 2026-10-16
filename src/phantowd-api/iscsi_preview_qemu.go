//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipreview"
)

// Synthetic proposal only. No backing, account or credential is opened.
const qemuISCSIPreviewFixture = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":18446744073709551615,
"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":18446744073709551615,
"shares":{"format":"phantowd-share-config","schema_version":1,"revision":18446744073709551615,
"volumes":[{"id":"bulk","filesystem_uuid":"11111111-2222-3333-4444-555555555555"}],"users":[{"id":"reader","name":"reader"}],"shares":[{"id":"share","name":"Fixture share","volume_id":"bulk","relative_path":".","grants":[{"user_id":"reader","access":"ro"}]}]},
"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":18446744073709551615,"volume_revision":18446744073709551615,"exports":[{"id":"aaaaaaaa-1111-2222-3333-444444444444","volume_id":"bulk","relative_path":"luns","clients":[{"network":"198.51.100.1/32","access":"ro","squash":"all","anonymous_uid":65534,"anonymous_gid":65534,"security":"sys"}]}]}},
"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":18446744073709551615,"volume_revision":18446744073709551615,
"backings":[{"id":"backing","volume_id":"bulk","relative_path":"luns/not-opened.img","capacity_bytes":9223372036854771712,"block_size":4096,"allocation":"sparse"}],
"targets":[{"id":"target","name":"iqn.2001-04.com.example:target","state":"enabled","luns":[{"id":"lun","number":0,"backing_id":"backing","access":"rw"}],
"initiators":[{"name":"iqn.2001-04.com.example:peer","authentication":{"mode":"chap","initiator_user":"private-user","initiator_secret_ref":"private-ref"},"grants":[{"lun_id":"lun","access":"ro"}]}]}]}}`

func exerciseQEMUISCSIPreviewHTTP(client *http.Client, origin, csrf string) error {
	for _, spec := range []struct {
		method, origin, csrf, body string
		status                     int
	}{
		{http.MethodPost, origin, csrf, qemuISCSIPreviewFixture, 200},
		{http.MethodPost, origin, "", qemuISCSIPreviewFixture, 403},
		{http.MethodPost, "https://attacker.invalid", csrf, qemuISCSIPreviewFixture, 403},
		{http.MethodPost, origin, csrf, strings.Replace(qemuISCSIPreviewFixture, `"volume_revision":18446744073709551615`, `"volume_revision":1`, 1), 422},
		{http.MethodGet, origin, csrf, "", 405},
	} {
		request, err := http.NewRequest(spec.method, origin+iscsiPreviewPath, strings.NewReader(spec.body))
		if err != nil {
			return errors.New("iSCSI preview request construction failed")
		}
		request.Header.Set("Origin", spec.origin)
		request.Header.Set("Content-Type", "application/json")
		if spec.csrf != "" {
			request.Header.Set("X-PhantoWD-CSRF", spec.csrf)
		}
		response, err := client.Do(request)
		if err != nil {
			return errors.New("iSCSI preview request failed")
		}
		data, err := readSelfTestResponse(response, iscsipreview.MaxOutputBytes)
		if err != nil || response.StatusCode != spec.status {
			return errors.New("iSCSI preview HTTP contract failed")
		}
		if spec.status == http.StatusOK {
			var p iscsipreview.Preview
			if json.Unmarshal(data, &p) != nil || p.Format != iscsipreview.Format || p.SchemaVersion != 2 ||
				p.Scope != "desired-policy-only" || p.Revision != "18446744073709551615" ||
				p.StorageValidated || p.CredentialsValidated || p.RuntimeValidated || p.ActivationAvailable ||
				len(p.Backings) != 1 || p.Backings[0].CapacityBytes != "9223372036854771712" ||
				p.SMBDefinitions != 1 || p.NFSDefinitions != 1 || p.Backings[0].SMBPathOverlapCount != 1 || p.Backings[0].NFSPathOverlapCount != 1 ||
				len(p.Targets) != 1 || p.Targets[0].DesiredState != "enabled" ||
				len(p.Targets[0].LUNs) != 1 || p.Targets[0].LUNs[0].Number != 0 ||
				len(p.Targets[0].Initiators) != 1 || len(p.Targets[0].Initiators[0].Grants) != 1 ||
				p.Targets[0].Initiators[0].Grants[0].Access != "ro" {
				return errors.New("iSCSI preview lost definitions or overstated authority")
			}
			for _, private := range []string{"private-user", "private-ref", "11111111-2222", "secret_ref", "initiator_user"} {
				if strings.Contains(string(data), private) {
					return errors.New("iSCSI preview disclosed private policy fields")
				}
			}
		}
	}
	// Keep the original transport (including TLS verification), but no cookie.
	anonymous := *client
	anonymous.Jar = nil
	response, err := anonymous.Post(origin+iscsiPreviewPath, "application/json", strings.NewReader(qemuISCSIPreviewFixture))
	if err != nil {
		return errors.New("anonymous iSCSI preview request failed")
	}
	if _, err := readSelfTestResponse(response, 4096); err != nil || response.StatusCode != http.StatusUnauthorized {
		return errors.New("anonymous iSCSI preview was not refused")
	}
	transport := "http"
	if strings.HasPrefix(origin, "https://") {
		transport = "https"
	}
	fmt.Printf("PHANTOWD_ISCSI_PREVIEW_HTTP_READY transport=%s authenticated=true csrf=true coherent=true exact_decimals=true redacted=true activation=false scope=synthetic-desired-only\n", transport)
	return nil
}
