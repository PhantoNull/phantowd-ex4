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
)

const qemuNetworkPreviewFixture = `{"format":"phantowd-network-policy","schema_version":1,"revision":18446744073709551615,"hostname":"nas-example",
"interfaces":[{"slot":"lan-1","ipv4":{"mode":"static","addresses":["192.0.2.10/16"],"default_route":true,"gateway":"192.0.2.1","metric":100},
"ipv6":{"mode":"static","addresses":["2001:db8:1::10/64"],"default_route":true,"gateway":"fe80::1","metric":100}},
{"slot":"lan-2","ipv4":{"mode":"dhcp","addresses":[],"default_route":false,"metric":0},"ipv6":{"mode":"auto","addresses":[],"default_route":false,"metric":0}}],
"routes":[{"slot":"lan-1","destination":"198.51.100.0/24","gateway":"192.0.2.2","metric":300}],
"dns":{"mode":"automatic","source":"lan-2","servers":[],"search_domains":["example.invalid"]}}`

func exerciseQEMUNetworkPreviewHTTP(client *http.Client, origin, csrf string) error {
	for _, spec := range []struct {
		method, origin, csrf, body string
		status                     int
	}{
		{http.MethodPost, origin, csrf, qemuNetworkPreviewFixture, 200},
		{http.MethodPost, origin, "", qemuNetworkPreviewFixture, 403},
		{http.MethodPost, "https://foreign.invalid", csrf, qemuNetworkPreviewFixture, 403},
		{http.MethodPost, origin, csrf, strings.Replace(qemuNetworkPreviewFixture, `"slot":"lan-2"`, `"slot":"eth0"`, 1), 422},
		{http.MethodGet, origin, csrf, "", 405},
	} {
		r, err := http.NewRequest(spec.method, origin+networkPreviewPath, strings.NewReader(spec.body))
		if err != nil {
			return errors.New("network preview request construction failed")
		}
		r.Header.Set("Origin", spec.origin)
		r.Header.Set("Content-Type", "application/json")
		if spec.csrf != "" {
			r.Header.Set("X-PhantoWD-CSRF", spec.csrf)
		}
		response, err := client.Do(r)
		if err != nil {
			return errors.New("network preview request failed")
		}
		data, err := readSelfTestResponse(response, networkPreviewLimit)
		if err != nil || response.StatusCode != spec.status {
			return errors.New("network preview HTTP contract failed")
		}
		if spec.status == 200 {
			var p networkPreview
			if json.Unmarshal(data, &p) != nil || p.Format != "phantowd-desired-network-preview" || p.SchemaVersion != 1 ||
				p.Scope != "submitted-desired-policy-only" || p.Revision != "18446744073709551615" || p.Hostname != "nas-example" ||
				p.Saved || p.Applied || p.InterfaceBindingValidated || p.KernelStateValidated || p.ConflictsValidated || p.ReachabilityValidated || p.ActivationAvailable ||
				len(p.Interfaces) != 2 || len(p.Interfaces[0].IPv4.Addresses) != 1 || p.Interfaces[0].IPv4.Addresses[0] != "192.0.2.10/16" ||
				p.Interfaces[0].IPv6.Gateway != "fe80::1" || p.Interfaces[1].IPv4.Mode != "dhcp" || p.Interfaces[1].IPv6.Mode != "auto" ||
				len(p.Routes) != 1 || p.Routes[0].Destination != "198.51.100.0/24" || p.DNS.Source != "lan-2" || len(p.Limitations) != 4 {
				return errors.New("network preview lost desired fields or overstated authority")
			}
		}
	}
	anonymous := *client
	anonymous.Jar = nil
	response, err := anonymous.Post(origin+networkPreviewPath, "application/json", strings.NewReader(qemuNetworkPreviewFixture))
	if err != nil {
		return errors.New("anonymous network preview request failed")
	}
	if _, err := readSelfTestResponse(response, 4096); err != nil || response.StatusCode != 401 {
		return errors.New("anonymous network preview not refused")
	}
	transport := "http"
	if strings.HasPrefix(origin, "https://") {
		transport = "https"
	}
	fmt.Printf("PHANTOWD_NETWORK_PREVIEW_HTTP_READY transport=%s authenticated=true csrf=true desired_only=true exact_revision=true apply=false scope=synthetic-submitted-only\n", transport)
	return nil
}
