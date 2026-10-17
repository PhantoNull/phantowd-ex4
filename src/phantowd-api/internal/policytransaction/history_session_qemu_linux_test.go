//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func TestHistorySessionsUnderOriginalWriter(t *testing.T) {
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if err := exerciseHistorySessions(context.Background(), c); errors.Is(err, ErrUnsupported) {
		t.Skip("unique mount identity/tmpfs unavailable; no positive session writer qualification")
	} else if err != nil {
		t.Fatal(err)
	}
}

func TestSessionRootCensusUsesExplicitProfile(t *testing.T) {
	for _, names := range [][]string{{}, {"policy"}, {"policy", "operations"},
		{"policy", "operations", "policy-session"}, {"policy", "operations", "unknown"},
		{"policy", "operations", "policy-session", "unknown"}} {
		dir := t.TempDir()
		for _, name := range names {
			if err := os.Mkdir(filepath.Join(dir, name), 0700); err != nil {
				t.Fatal(err)
			}
		}
		f, err := os.Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		old := len(names) == 2 && names[0] == "policy" && names[1] == "operations"
		newProfile := len(names) == 3 && names[2] == "policy-session"
		for i := 0; i < 2; i++ {
			if rootCensus(f) != old || rootCensusFor(f, true) != newProfile {
				t.Fatal("census adopted foreign/missing/other-profile roles or reused cursor")
			}
		}
		if f.Close() != nil {
			t.Fatal("census parent close")
		}
	}
}

func TestSessionProfileRejectsUnsupportedCombinationsBeforeEffects(t *testing.T) {
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	for _, spec := range []struct {
		history     bool
		medium      disposableMedium
		crash, plan *disposableCrash
	}{{false, disposableTmpfs, nil, nil}, {true, disposableFixedExt4, nil, nil},
		{true, disposableTmpfs, &disposableCrash{}, nil}, {true, disposableTmpfs, nil, &disposableCrash{}}} {
		w, err := newDisposableProfile(context.Background(), testInstallation, c, spec.crash, spec.history, spec.plan, spec.medium, true)
		if w != nil || err != ErrInvalid {
			t.Fatal("unsupported profile did not refuse before namespace creation")
		}
	}
	var absent *writer
	if absent.sealSession(context.Background()) != ErrInvalid || (&writer{}).sealSession(context.Background()) != ErrInvalid {
		t.Fatal("invalid session lifetime admitted")
	}
}
