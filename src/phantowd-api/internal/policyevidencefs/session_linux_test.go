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
	"golang.org/x/sys/unix"
)

func sessionHistoryFixture(t *testing.T) (string, []byte) {
	t.Helper()
	root, base := historyFixture(t)
	o, _ := policyevidence.DeclareEpochOpening(installation, strings.Repeat("b", 32), 1, base)
	opening, _ := policyevidence.EncodeEpochOpening(o)
	c, _ := policyevidence.DeclareEpochClosure(opening, []byte(policyJSON))
	closing, _ := policyevidence.EncodeEpochClosure(c)
	wire, err := json.Marshal(map[string]any{"format": "phantowd-policy-session-journal-experimental", "schema_version": 1, "revision": 2, "installation_id": installation, "opening": base64.StdEncoding.EncodeToString(opening), "closure": base64.StdEncoding.EncodeToString(closing)})
	if err != nil || os.Mkdir(filepath.Join(root, "policy-session"), 0700) != nil || os.WriteFile(filepath.Join(root, "policy-session/epoch.json"), wire, 0600) != nil {
		t.Fatal("session fixture")
	}
	return root, base
}

func TestSessionHistoryObserverOriginalLifetime(t *testing.T) {
	root, checkpoint := sessionHistoryFixture(t)
	a, err := OpenSessionHistory(context.Background(), root, installation, checkpoint)
	if errors.Is(err, ErrUnsupported) && a == nil {
		t.Skip("unique mount identity unavailable; no positive session observer lifecycle")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if a.Close() != nil {
			t.Error("close")
		}
	}()
	checkpoint[0] = '!'
	if d, err := a.Observe(context.Background()); err != ErrInvalid || d.Kind() != "" {
		t.Fatal("wrong profile silently downgraded")
	}
	copyObserver := *a
	if _, err := copyObserver.ObserveSession(context.Background()); err != ErrInvalid {
		t.Fatal("copy admitted")
	}
	for range 2 {
		d, err := a.ObserveSession(context.Background())
		if err != nil || d.Kind() != policyevidence.ClosureSessionHistoryObserved {
			t.Fatal("joined observer", d, err)
		}
		for _, name := range []string{"", "policy", "operations", "policy-session"} {
			f, err := os.Open(filepath.Join(root, name))
			if err != nil {
				t.Fatal(err)
			}
			locked := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if f.Close() != nil || !errors.Is(locked, unix.EWOULDBLOCK) {
				t.Fatal("original lock gap")
			}
		}
	}
}

func TestSessionHistoryRefusesInvalidInputsBeforeFilesystem(t *testing.T) {
	for _, c := range [][]byte{nil, {}, []byte(`{}`)} {
		if a, err := OpenSessionHistory(context.Background(), "/missing-session-root", installation, c); a != nil || err != ErrInvalid {
			t.Fatal("invalid checkpoint reached filesystem")
		}
	}
	if a, err := openProfile(context.Background(), "/missing-session-root", installation, true, []byte(policyJSON), true); a != nil || err != ErrInvalid {
		t.Fatal("mixed profile reached filesystem")
	}
	var a *Observer
	if _, err := a.ObserveSession(context.Background()); err != ErrInvalid {
		t.Fatal("nil handle admitted")
	}
	if _, err := (&Observer{}).ObserveSession(context.Background()); err != ErrInvalid {
		t.Fatal("zero handle admitted")
	}
	s := &state{}
	if len(s.directoryObjects()) != 3 {
		t.Fatal("legacy directory roster enlarged")
	}
	s.sessionProfile = true
	if len(s.directoryObjects()) != 4 {
		t.Fatal("session directory roster incomplete")
	}
}
