//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"net/http"
	"strings"
	"syscall"
	"testing"
)

type qemuFailedPreviewTransport struct{}

func (qemuFailedPreviewTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	if r.Body != nil {
		_ = r.Body.Close()
	}
	return nil, errors.Join(syscall.ECONNRESET, errors.New("private diagnostic must not escape"))
}

func TestQEMUTLSLoopbackSmoke(t *testing.T) {
	// Transport diagnostics must identify the failing case without printing the
	// URL, cookies, request body or raw underlying error.
	private := &http.Client{Transport: qemuFailedPreviewTransport{}}
	if err := exerciseQEMUISCSIPreviewHTTP(private, "https://private-origin.invalid", "private-token"); err == nil ||
		!strings.Contains(err.Error(), "case=0") || !strings.Contains(err.Error(), "errno=") || strings.Contains(err.Error(), "private") {
		t.Fatal("fixture transport diagnostic missing or unredacted")
	}
	if err := exerciseQEMUTLSWithAccountFactory(func(dir string) (*accountStore, error) {
		return openTestAccountStore(t, dir), nil
	}); err != nil {
		t.Fatal(err)
	}
}
