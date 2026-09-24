//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"strings"
	"testing"
)

func TestQEMUDashboardAssetsMatchSelfTest(t *testing.T) {
	for _, asset := range qemuDashboardAssets {
		assetPath, _ := dashboardAsset(asset.path)
		data, err := dashboardFiles.ReadFile(assetPath)
		if err != nil {
			t.Fatalf("read embedded asset %q: %v", asset.path, err)
		}
		for _, marker := range asset.markers {
			if !strings.Contains(string(data), marker) {
				t.Errorf("QEMU self-test marker %q is absent from embedded asset %q", marker, asset.path)
			}
		}
	}
}
