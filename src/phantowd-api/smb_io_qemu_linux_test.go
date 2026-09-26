//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestQEMUSMBDenialEvidence(t *testing.T) {
	const code = "NT_STATUS_ACCOUNT_DISABLED"
	for _, test := range []struct {
		output string
		err    error
		want   bool
	}{
		{code, &exec.ExitError{}, true},
		{code, nil, false},
		{code, context.DeadlineExceeded, false},
		{code, errors.New("connection refused"), false},
		{"NT_STATUS_LOGON_FAILURE", &exec.ExitError{}, false},
		{"", &exec.ExitError{}, false},
	} {
		if got := smbFixtureDenied([]byte(test.output), test.err, code); got != test.want {
			t.Fatalf("denial evidence %q (%T): got %v, want %v", test.output, test.err, got, test.want)
		}
	}
}

func TestQEMUSMBEffectiveFixture(t *testing.T) {
	p, err := qemuSMBPolicy()
	if err != nil || len(p.Shares) != 2 {
		t.Fatal("fixture policy", err)
	}
	for _, expected := range []string{"[PolicyShare]", "[UnixDenied]", "valid users = qpreader qpwriter", "read list = qpreader", "write list = qpwriter", "follow symlinks = no"} {
		if !strings.Contains(p.Sections, expected) {
			t.Fatal("missing fixture rule", expected)
		}
	}
	if strings.Contains(p.Sections, "qpoutsider") {
		t.Fatal("outsider granted access")
	}
	if runtime.GOARCH != "arm" {
		if err := runQEMUSMBTest(); err == nil {
			t.Fatal("host mutation guard failed")
		}
		if err := exerciseQEMUUnixIdentity(); err == nil {
			t.Fatal("Unix identity host mutation guard failed")
		}
	}
	for _, address := range []string{"0100007F:05A5", "00000000:05A5", "0100000A:05A5", "00000000000000000000000000000000:05A5", "00000000000000000000000001000000:05A5"} {
		err := checkSMBFixtureListeners("0: " + address + " 00000000:0000 0A")
		if (err == nil) != (address == "0100007F:05A5") {
			t.Fatal("listener boundary", address, err)
		}
	}
}
