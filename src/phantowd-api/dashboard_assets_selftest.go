//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"errors"
	"io"
	"net/http"
)

const qemuDashboardAssetLimit = 64 * 1024

// One assertion roster for the existing HTTP and trusted temporary HTTPS
// loopback fixtures. Matching this binary's embedded bytes is not source/release
// authenticity, browser execution or qualification of a product certificate.
// The caller retains its fixed timeout, proxy/redirect policy and TLS trust.
func exerciseQEMUDashboardAssets(client *http.Client, origin string) error {
	for _, asset := range qemuDashboardAssets {
		path, _ := dashboardAsset(asset.path)
		expected, err := dashboardFiles.ReadFile(path)
		if err != nil || len(expected) == 0 || len(expected) > qemuDashboardAssetLimit {
			return errors.New("invalid embedded dashboard assertion source")
		}
		response, err := client.Get(origin + asset.path)
		if err != nil {
			return errors.New("dashboard loopback request failed")
		}
		data, readErr := io.ReadAll(io.LimitReader(response.Body, qemuDashboardAssetLimit+1))
		closeErr := response.Body.Close()
		if readErr != nil || closeErr != nil || len(data) > qemuDashboardAssetLimit || response.StatusCode != http.StatusOK {
			return errors.New("invalid dashboard asset response")
		}
		csp := "default-src 'none'; sandbox"
		if asset.path == "/" {
			csp = "default-src 'none'; style-src 'self'; script-src 'self'; img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
		}
		for _, header := range [][2]string{
			{"Content-Type", asset.contentType}, {"Cache-Control", "no-store"},
			{"X-Content-Type-Options", "nosniff"}, {"Content-Security-Policy", csp},
		} {
			values := response.Header.Values(header[0])
			if len(values) != 1 || values[0] != header[1] {
				return errors.New("invalid dashboard asset headers")
			}
		}
		if !bytes.Equal(data, expected) {
			return errors.New("dashboard asset differs from embedded bytes")
		}
		for _, marker := range asset.markers {
			if !bytes.Contains(data, []byte(marker)) {
				return errors.New("dashboard asset failed its content assertion")
			}
		}
	}
	return nil
}
