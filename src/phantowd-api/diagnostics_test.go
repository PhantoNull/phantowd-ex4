// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"strings"
	"testing"
	"testing/fstest"
	"time"
)

func fixtureProc() fstest.MapFS {
	return fstest.MapFS{
		"sys/kernel/osrelease": {Data: []byte("6.18.53\n")},
		"uptime":               {Data: []byte("123.50 456.75\n")},
		"meminfo":              {Data: []byte("MemTotal: 262144 kB\nMemAvailable: 196608 kB\nOther: 1 kB\n")},
	}
}

func TestCollectSystem(t *testing.T) {
	now := time.Date(2026, 9, 18, 12, 0, 0, 0, time.FixedZone("local", 7200))
	snapshot, err := collectSystem(fixtureProc(), now)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.SchemaVersion != 1 || snapshot.Target != "qemu-armv5" || snapshot.Mode != "development" || snapshot.Flashable || snapshot.HardwareValidated {
		t.Fatalf("incorrect development boundary: %+v", snapshot)
	}
	if snapshot.Kernel != "6.18.53" || snapshot.UptimeSeconds != 123.5 || snapshot.Memory.TotalBytes != 268435456 || snapshot.Memory.AvailableBytes != 201326592 {
		t.Fatalf("incorrect proc conversion: %+v", snapshot)
	}
	if !snapshot.ObservedAt.Equal(now) || snapshot.ObservedAt.Location() != time.UTC {
		t.Fatal("observation time must preserve the instant in UTC")
	}
}

func TestCollectSystemFailures(t *testing.T) {
	for _, test := range []struct{ name, path, data string }{
		{"empty kernel", "sys/kernel/osrelease", ""},
		{"multiline kernel", "sys/kernel/osrelease", "6.18\nsecret"},
		{"long kernel", "sys/kernel/osrelease", strings.Repeat("x", 129)},
		{"oversized proc", "meminfo", strings.Repeat("x", maxProcBytes+1)},
		{"malformed uptime", "uptime", "NaN 0"},
		{"missing memory", "meminfo", "MemTotal: 123 kB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			proc := fixtureProc()
			proc[test.path] = &fstest.MapFile{Data: []byte(test.data)}
			if _, err := collectSystem(proc, time.Now()); err == nil {
				t.Fatal("invalid proc data accepted")
			}
		})
	}
	for _, path := range []string{"sys/kernel/osrelease", "uptime", "meminfo"} {
		t.Run("missing "+path, func(t *testing.T) {
			proc := fixtureProc()
			delete(proc, path)
			if _, err := collectSystem(proc, time.Now()); err == nil {
				t.Fatal("missing proc data accepted")
			}
		})
	}
}

func TestParseUptime(t *testing.T) {
	for _, data := range []string{"", "0", "1 2 3", "-1 0", "1 -2", "NaN 0", "0 NaN", "+Inf 0", "0 -Inf", "oops 0", "1e999 0"} {
		t.Run(data, func(t *testing.T) {
			if _, err := parseUptime(data); err == nil {
				t.Fatalf("accepted %q", data)
			}
		})
	}
	if value, err := parseUptime("0.00 0.00\n"); err != nil || value != 0 {
		t.Fatal("valid zero uptime rejected")
	}
}

func TestParseMemory(t *testing.T) {
	for _, test := range []struct{ name, data string }{
		{"empty", ""},
		{"missing available", "MemTotal: 1 kB"},
		{"missing total", "MemAvailable: 1 kB"},
		{"wrong unit", "MemTotal: 4 MB\nMemAvailable: 2 kB"},
		{"negative", "MemTotal: -1 kB\nMemAvailable: 0 kB"},
		{"extra field", "MemTotal: 4 kB extra\nMemAvailable: 2 kB"},
		{"duplicate", "MemTotal: 4 kB\nMemTotal: 4 kB\nMemAvailable: 2 kB"},
		{"overflow", "MemTotal: 18446744073709551615 kB\nMemAvailable: 0 kB"},
		{"invalid integer", "MemTotal: hello kB\nMemAvailable: 0 kB"},
		{"zero total", "MemTotal: 0 kB\nMemAvailable: 0 kB"},
		{"inconsistent", "MemTotal: 1 kB\nMemAvailable: 2 kB"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseMemory(test.data); err == nil {
				t.Fatal("invalid memory information accepted")
			}
		})
	}
	if value, err := parseMemory("MemTotal: 1 kB\nMemAvailable: 0 kB"); err != nil || value.AvailableBytes != 0 {
		t.Fatal("valid zero available memory rejected")
	}
}

func FuzzParseMemory(f *testing.F) {
	f.Add("MemTotal: 1024 kB\nMemAvailable: 512 kB\n")
	f.Add("MemTotal: 18446744073709551615 kB\n")
	f.Fuzz(func(t *testing.T, data string) {
		memory, err := parseMemory(data)
		if err == nil && (memory.TotalBytes == 0 || memory.AvailableBytes > memory.TotalBytes) {
			t.Fatal("successful parse violated memory invariants")
		}
	})
}
