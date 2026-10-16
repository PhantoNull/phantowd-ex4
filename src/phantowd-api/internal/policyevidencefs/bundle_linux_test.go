//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func bundleFixture(t *testing.T) string {
	t.Helper()
	current := []byte(policyJSON)
	base := []byte(strings.ReplaceAll(policyJSON, ":2", ":1"))
	intent, receipt := records(current, base)
	wire, err := json.Marshal(map[string]any{"format": "phantowd-policy-operation-bundle-experimental", "schema_version": 1,
		"revision": 2, "phase": "local-confirmed", "installation_id": installation,
		"base": base64.StdEncoding.EncodeToString(base), "intent": base64.StdEncoding.EncodeToString(intent), "receipt": base64.StdEncoding.EncodeToString(receipt)})
	if err != nil {
		t.Fatal(err)
	}
	root := fixture(t, current, nil, nil)
	if os.WriteFile(filepath.Join(root, "operations/operation.json"), wire, 0600) != nil {
		t.Fatal("bundle fixture")
	}
	return root
}

func openBundleSupported(t *testing.T, root string) *Observer {
	t.Helper()
	a, err := OpenBundle(context.Background(), root, installation)
	if errors.Is(err, ErrUnsupported) && a == nil {
		t.Skip("unique mount identity unavailable; no bundle lifecycle qualification")
	}
	if err != nil {
		t.Fatal("bundle open", err)
	}
	t.Cleanup(func() {
		if a.Close() != nil {
			t.Error("bundle close")
		}
	})
	return a
}

func TestBundleProfileIsFixedAndNeverAutodetected(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(map[bool]string{false: "bundle-with-legacy-opener", true: "legacy-with-bundle-opener"}[legacy], func(t *testing.T) {
			root := bundleFixture(t)
			opener := Open
			if legacy {
				root = fixture(t, []byte(policyJSON), []byte("private"), nil)
				opener = OpenBundle
			}
			a, err := opener(context.Background(), root, installation)
			if errors.Is(err, ErrUnsupported) && a == nil {
				t.Skip("unique mount identity unavailable")
			}
			if a != nil {
				_ = a.Close()
				t.Fatal("foreign profile accepted")
			}
			if !errors.Is(err, ErrUnsafe) {
				t.Fatal("foreign profile not explicitly refused", err)
			}
		})
	}
}

func TestBundlePendingRefusesBeforeReadingCurrentOrOperation(t *testing.T) {
	for _, pending := range []string{"policy/.nas-services.pending", "operations/.operation.pending"} {
		t.Run(pending, func(t *testing.T) {
			root := bundleFixture(t)
			if os.WriteFile(filepath.Join(root, pending), []byte("malformed private staged data"), 0600) != nil {
				t.Fatal("pending fixture")
			}
			a := openBundleSupported(t, root)
			a.state.readAt = func(*os.File, []byte, int64) (int, error) { t.Error("read despite pending metadata"); return 0, ErrIO }
			for range 2 {
				if d, err := a.Observe(context.Background()); err != ErrReview || d.Kind() != "" {
					t.Fatal("pending promoted", d, err)
				}
			}
		})
	}
}

func TestBundleProfileReadsAndRetainsReviewAfterRestoration(t *testing.T) {
	root := bundleFixture(t)
	a := openBundleSupported(t, root)
	if d, err := a.Observe(context.Background()); err != nil || d.Kind() != policyevidence.LocalConfirmationObserved {
		t.Fatal(d, err)
	}
	path := filepath.Join(root, "operations/operation.json")
	if os.Chmod(path, 0400) != nil || os.Chmod(path, 0600) != nil {
		t.Fatal("drift fixture")
	}
	for range 2 {
		if d, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) || d.Kind() != "" {
			t.Fatal("restoration cleared review", d, err)
		}
	}
}
