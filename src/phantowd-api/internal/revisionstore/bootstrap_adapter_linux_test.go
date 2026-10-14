//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

func TestNASBootstrapAdapterNeverImportsLegacyState(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	got, err := naspolicystore.ObserveBootstrap(context.Background(), dir)
	if err != nil || got.Kind != revisionstore.BootstrapEmptyDirectory {
		t.Fatal("fixed empty-directory observation", got, err)
	}
	name := filepath.Join(dir, "file-services.json")
	if err := os.WriteFile(name, []byte("legacy evidence"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err = naspolicystore.ObserveBootstrap(context.Background(), dir)
	if err != nil || got.Kind != revisionstore.BootstrapUnrecognizedEntries || got.Revision != 0 {
		t.Fatal("implicit legacy import or initialization", got, err)
	}
	if data, err := os.ReadFile(name); err != nil || string(data) != "legacy evidence" {
		t.Fatal("legacy evidence changed", err)
	}
	if names, err := os.ReadDir(dir); err != nil || len(names) != 1 {
		t.Fatal("observer created current state", names, err)
	}
	a, err := naspolicystore.OpenBootstrapAuthority(context.Background(), dir)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if observed, err := a.Observe(context.Background()); err != nil || observed.Kind != revisionstore.BootstrapUnrecognizedEntries || observed.Revision != 0 {
		t.Fatal("fixed authority imported legacy evidence", observed, err)
	}
	if other, err := naspolicystore.Open(dir); !errors.Is(err, naspolicystore.ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("fixed authority did not retain lock", err)
	}
}
