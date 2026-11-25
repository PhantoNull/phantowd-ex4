// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
)

func TestProvisionAdministratorPersistsLocalEnrollment(t *testing.T) {
	dir := privateProvisioningDirectory(t)
	store, err := admincredentials.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	input, err := json.Marshal(setupRequest{Username: "nas-admin", Password: testAdminPassword})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := provisionAdministrator(ctx, bytes.NewReader(input), store); err != nil {
		t.Fatal(err)
	}
	blockedInput, err := json.Marshal(setupRequest{Username: "other-admin", Password: testAdminPassword})
	if err != nil {
		t.Fatal(err)
	}
	if err := provisionAdministrator(ctx, bytes.NewReader(blockedInput), store); !errors.Is(err, errAdministratorProvisioning) {
		t.Fatalf("re-enrollment was not refused: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	accounts := openTestAccountStore(t, dir)
	if valid, err := accounts.authenticate(ctx, "nas-admin", testAdminPassword); err != nil || !valid {
		t.Fatalf("persisted administrator could not authenticate: %v", err)
	}
	if raw, err := os.ReadFile(filepath.Join(dir, "accounts.json")); err != nil || bytes.Contains(raw, []byte(testAdminPassword)) {
		t.Fatalf("credential record unavailable or holds plaintext: %v", err)
	}
}

func TestProvisionAdministratorRefusesMalformedInput(t *testing.T) {
	dir := privateProvisioningDirectory(t)
	store, err := admincredentials.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	for _, input := range []string{
		`{"username":"admin","Username":"other","password":"over-fifteen-characters"}`,
		`{"username":"admin","password":null}`,
		`{"username":"admin","password":"short"}`,
		`{"username":"admin","password":"over-fifteen-characters"}{}`,
		strings.Repeat(" ", 8193),
	} {
		if err := provisionAdministrator(context.Background(), strings.NewReader(input), store); !errors.Is(err, errAdministratorProvisioning) {
			t.Fatalf("invalid input was not refused: %v", err)
		}
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatalf("invalid input changed directory contents: %v", err)
	}
}

func privateProvisioningDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}
