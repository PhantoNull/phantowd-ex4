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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

const historyID = "aaaaaaaabbbbccccddddeeeeeeeeeeee"

func historyFixture(t *testing.T) (string, []byte) {
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
	if err := os.WriteFile(filepath.Join(root, "operations", historyID+".json"), wire, 0600); err != nil {
		t.Fatal(err)
	}
	return root, base
}

func TestHistoryObserverRetainsActualLocksAndOwnedCheckpoint(t *testing.T) {
	root, checkpoint := historyFixture(t)
	a, err := OpenHistory(context.Background(), root, installation, checkpoint)
	if errors.Is(err, ErrUnsupported) && a == nil {
		t.Skip("unique mount identity unavailable; no history lifecycle qualification")
	}
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	checkpoint[0] = '!'
	for range 2 {
		d, err := a.Observe(context.Background())
		if err != nil || d.Kind() != policyevidence.LocalConfirmationObserved {
			t.Fatal("history read", d, err)
		}
		other, err := naspolicystore.Open(filepath.Join(root, "policy"))
		if other != nil || !errors.Is(err, naspolicystore.ErrBusy) {
			if other != nil {
				_ = other.Close()
			}
			t.Fatal("policy lock gap", err)
		}
	}
}

func TestHistoryCheckpointValidationPrecedesFilesystemAccess(t *testing.T) {
	for _, checkpoint := range [][]byte{nil, {}, []byte("private malformed checkpoint")} {
		a, err := OpenHistory(context.Background(), "/unavailable-history-layout", installation, checkpoint)
		if a != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid checkpoint reached filesystem", err)
		}
	}
}

func TestHistoryPendingRefusesBeforeAnyContentRead(t *testing.T) {
	root, checkpoint := historyFixture(t)
	if err := os.WriteFile(filepath.Join(root, "operations", historyPending), []byte("not parsed"), 0600); err != nil {
		t.Fatal(err)
	}
	a, err := OpenHistory(context.Background(), root, installation, checkpoint)
	if errors.Is(err, ErrUnsupported) && a == nil {
		t.Skip("unique mount identity unavailable; no history lifecycle qualification")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	reads := 0
	a.state.readAt = func(*os.File, []byte, int64) (int, error) {
		reads++
		return 0, errors.New("must never read staged contents")
	}
	for range 2 {
		d, err := a.Observe(context.Background())
		if !errors.Is(err, ErrReview) || d.Kind() != "" || reads != 0 {
			t.Fatal("pending content read or admitted", d, err, reads)
		}
	}
}
