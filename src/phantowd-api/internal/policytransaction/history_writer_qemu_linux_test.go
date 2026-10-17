//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func TestDisposableHistoryWriterAdvancesUnderOriginalLocks(t *testing.T) {
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	w, err := newDisposableHistory(context.Background(), testInstallation, c)
	if errors.Is(err, ErrUnsupported) && w == nil {
		t.Skip("unique mount identity unavailable; no history writer lifecycle qualification")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if w.close() != nil || w.discard() != nil {
			t.Error("fixture disposal")
		}
	}()
	for _, n := range []uint64{2, 3} {
		fixtureRevision(&c, n)
		outcome, err := w.executeHistory(context.Background(), c)
		if err != nil || outcome.revision != n || !actualLocksHeld(w) {
			t.Fatal("history advance/lock gap", err)
		}
	}
}
