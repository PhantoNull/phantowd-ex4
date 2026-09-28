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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
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
		if err := exerciseQEMUDisabledPasswordBoundary(nil, serviceaccounts.Account{}); err == nil {
			t.Fatal("disabled-password host mutation guard failed")
		}
	}
	for _, address := range []string{"0100007F:05A5", "00000000:05A5", "0100000A:05A5", "00000000000000000000000000000000:05A5", "00000000000000000000000001000000:05A5"} {
		err := checkSMBFixtureListeners("0: " + address + " 00000000:0000 0A")
		if (err == nil) != (address == "0100007F:05A5") {
			t.Fatal("listener boundary", address, err)
		}
	}
}

func TestQEMUSMBProvisionParser(t *testing.T) {
	account := serviceaccounts.Account{ID: "second", Name: "qpsecond", UID: 1805, GID: 1805, State: serviceaccounts.Disabled}
	output := []byte("Unix username: qpwriter\nUser SID: S-1-5-21-1-2-3-1001\nAccount Flags: [U          ]\n\n" +
		"Unix username: qpsecond\nUser SID: S-1-5-21-1-2-3-1002\nAccount Flags: [UD         ]\n")
	observation, err := parseQEMUSMBObservation(output, account)
	if err != nil || observation != (smbprovision.Observation{Present: true, Name: account.Name,
		UID: account.UID, GID: account.GID, SID: "S-1-5-21-1-2-3-1002", Disabled: true}) {
		t.Fatal("disabled passdb entry was not parsed", observation, err)
	}
	if absent, err := parseQEMUSMBObservation([]byte("Unix username: qpwriter\nUser SID: S-1-5-21-1-2-3-1001\nAccount Flags: [U]\n"), account); err != nil || absent != (smbprovision.Observation{}) {
		t.Fatal("absent passdb entry was not represented exactly", absent, err)
	}
	duplicate := append(append([]byte{}, output...), []byte("\nUnix username: qpsecond\nUser SID: S-1-5-21-1-2-3-1003\nAccount Flags: [D]\n")...)
	if _, err := parseQEMUSMBObservation(duplicate, account); err == nil {
		t.Fatal("duplicate passdb names were accepted")
	}
	malformed := []byte("Unix username: qpsecond\nUser SID: malformed\nAccount Flags: disabled\n")
	if _, err := parseQEMUSMBObservation(malformed, account); err == nil {
		t.Fatal("malformed passdb flags were accepted")
	}
}
