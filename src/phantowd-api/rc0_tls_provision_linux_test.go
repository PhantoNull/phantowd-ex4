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
	if !validRC0TLSFingerprint(rc0TLSBundleFingerprint(bundle, origin, now)) {
		t.Fatal("matching current identity was refused")
	}
	for _, wrong := range []string{"http://nas.example:8443", "https://other.example:8443", origin + "/"} {
		if rc0TLSBundleFingerprint(bundle, wrong, now) != "" {
			t.Fatal("unsafe origin was accepted")
		}
	}
	if rc0TLSBundleFingerprint(bundle, origin, now.Add(48*time.Hour)) != "" ||
		rc0TLSBundleFingerprint(bundle, origin, now.Add(-2*time.Hour)) != "" ||
		rc0TLSBundleFingerprint(append(bundle, make([]byte, maxTLSIdentityBytes)...), origin, now) != "" {
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
	if err := publishRC0TLS(root, []byte("replacement"), false); !errors.Is(err, errRC0TLSProvision) {
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
	if err := publishRC0TLS(root, data, false); err != nil {
		t.Fatal(err)
	}
	if err := publishRC0TLS(root, []byte("replacement"), false); !errors.Is(err, errRC0TLSProvision) {
		t.Fatal("installation overwrote a published identity")
	}
	if info, err := os.Stat(identity); err != nil || info.Mode() != 0600 {
		t.Fatal("published identity lacks private mode")
	}
	if raw, err := os.ReadFile(identity); err != nil || !bytes.Equal(raw, data) {
		t.Fatal("published identity bytes changed")
	}
	if err := os.WriteFile(stage, []byte("interrupted renewal"), 0600); err != nil {
		t.Fatal(err)
	}
	replacement := []byte("replacement")
	if err := publishRC0TLS(root, replacement, true); !errors.Is(err, errRC0TLSProvision) {
		t.Fatal("replacement proceeded with staged evidence")
	}
	if err := os.Remove(stage); err != nil {
		t.Fatal(err)
	}
	if err := publishRC0TLS(root, replacement, true); err != nil {
		t.Fatal(err)
	}
	if raw, err := os.ReadFile(identity); err != nil || !bytes.Equal(raw, replacement) {
		t.Fatal("replacement identity bytes differ")
	}
}
