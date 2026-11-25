// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRC0TLSBundleRequiresMatchingCurrentlyValidHTTPSIdentity(t *testing.T) {
	const origin = "https://nas.example:8443"
	cert, key := writeTestTLSFiles(t, "nas.example")
	identity := writeTestTLSIdentity(t, cert, key)
	bundle, err := os.ReadFile(identity.Name())
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if !validRC0TLSBundle(bundle, origin, now) {
		t.Fatal("matching current identity was refused")
	}
	for _, wrong := range []string{"http://nas.example:8443", "https://other.example:8443", origin + "/"} {
		if validRC0TLSBundle(bundle, wrong, now) {
			t.Fatal("unsafe origin was accepted")
		}
	}
	if validRC0TLSBundle(bundle, origin, now.Add(48*time.Hour)) ||
		validRC0TLSBundle(bundle, origin, now.Add(-2*time.Hour)) ||
		validRC0TLSBundle(append(bundle, make([]byte, maxTLSIdentityBytes)...), origin, now) {
		t.Fatal("expired, future or oversized identity was accepted")
	}
}

func TestRC0TLSPublicationPreservesStagingAndDoesNotReplace(t *testing.T) {
	dir := t.TempDir()
	root := mustOpenRC0Fixture(t, dir)
	stage := filepath.Join(dir, rc0TLSStage)
	identity := filepath.Join(dir, rc0TLSIdentity)
	if err := os.WriteFile(stage, []byte("interrupted"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := publishInitialRC0TLS(root, []byte("replacement")); !errors.Is(err, errRC0TLSProvision) {
		t.Fatal("installation proceeded with staged evidence")
	}
	if data, err := os.ReadFile(stage); err != nil || string(data) != "interrupted" {
		t.Fatal("staging was modified")
	}
	if _, err := os.Lstat(identity); !os.IsNotExist(err) {
		t.Fatal("final role appeared with staged evidence")
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	data := []byte("validated identity fixture")
	if err := publishInitialRC0TLS(root, data); err != nil {
		t.Fatal(err)
	}
	if err := publishInitialRC0TLS(root, []byte("replacement")); !errors.Is(err, errRC0TLSProvision) {
		t.Fatal("installation overwrote a published identity")
	}
	if info, err := os.Stat(identity); err != nil || info.Mode() != 0600 {
		t.Fatal("published identity lacks private mode")
	}
	if raw, err := os.ReadFile(identity); err != nil || !bytes.Equal(raw, data) {
		t.Fatal("published identity bytes changed")
	}
}
