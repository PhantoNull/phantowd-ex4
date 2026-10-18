//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestKernelThermalNativeReadOnlyObservation(t *testing.T) {
	got := collectKernelThermal(os.DirFS("/sys"))
	if got.SchemaVersion != 1 || got.Scope != "kernel-thermal-sysfs-only" || !got.ReadOnly || got.HardwareQualified || got.ControlAvailable ||
		got.Zones == nil || len(got.Zones) > maxKernelThermalZones {
		t.Fatal("native observation lost its non-authoritative boundary")
	}
	if got.Status != "available" && got.Status != "partial" && got.Status != "unavailable" {
		t.Fatal("unknown native observation status")
	}
	if got.Status == "unavailable" && len(got.Zones) != 0 {
		t.Fatal("unavailable native set retained values")
	}
	for _, zone := range got.Zones {
		if (zone.Status == "reported") != (zone.MilliCelsius != nil) {
			t.Fatal("missing native value became a number")
		}
	}
	data, err := json.Marshal(got)
	if err != nil || len(data) > 16*1024 {
		t.Fatal("native observation exceeded reply envelope")
	}
	// Deliberately no driver types, temperatures or machine-specific identifiers.
	t.Logf("kernel thermal observation: status=%s zones=%d hardware_qualified=false control_available=false", got.Status, len(got.Zones))
	if len(got.Zones) == 0 {
		t.Log("no nonempty sensor observation qualified on this host")
	}
}
