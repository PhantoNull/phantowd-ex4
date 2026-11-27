//go:build linux && qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

func TestSambaServiceDocumentsKeepOneEndpointAndGrantedLookup(t *testing.T) {
	candidate := plannedDocumentCandidate(t)
	address := netip.MustParseAddr("192.0.2.21")
	docs, err := sambaServiceDocuments(candidate, address)
	if err != nil || len(docs) != 7 {
		t.Fatalf("render service documents: %v", err)
	}
	passwd, group, nss, sections, _, err := candidate.Documents()
	if err != nil || docs["passwd"] != passwd || docs["group"] != group || docs["nsswitch.conf"] != nss ||
		strings.Contains(docs["passwd"], "qpmanaged:") || !strings.Contains(docs["passwd"], "qpsecond:") ||
		docs[sambaSettingsPath] != "[global]\ninterfaces = 192.0.2.21\n"+sambaServiceSettings+sections {
		t.Fatal("service configuration diverged from the exact endpoint or isolated candidate")
	}
	for _, value := range []string{"0.0.0.0", "127.0.0.1", "169.254.1.2", "224.0.0.1", "255.255.255.255", "::1", "::ffff:192.0.2.21"} {
		if result, err := sambaServiceDocuments(candidate, netip.MustParseAddr(value)); result != nil || !errors.Is(err, ErrInvalid) {
			t.Fatalf("accepted unsupported endpoint %s", value)
		}
	}
	if result, err := sambaServiceDocuments(fileserviceplan.SambaIsolatedCandidate{}, address); result != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("accepted missing isolated candidate")
	}
}
