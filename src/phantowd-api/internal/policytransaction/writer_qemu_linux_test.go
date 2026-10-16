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

func TestDisposableWriterRejectsInvalidBeforeNamespace(t *testing.T) {
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if w, err := newDisposable(nil, testInstallation, c); w != nil || err != ErrInvalid {
		t.Fatal("nil context")
	}
	if w, err := newDisposable(context.Background(), "bad", c); w != nil || err != ErrInvalid {
		t.Fatal("invalid installation")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if w, err := newDisposable(ctx, testInstallation, c); w != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled entry")
	}
	var zero writer
	if _, err := zero.execute(context.Background(), c); err != ErrInvalid {
		t.Fatal("zero writer")
	}
}
func TestDisposableWriterActualCurrentKernel(t *testing.T) {
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	w, err := newDisposable(context.Background(), testInstallation, c)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("mandatory unique mount-ID/tmpfs support absent: no positive writer qualification")
	}
	if w != nil {
		if closeErr := w.close(); closeErr != nil {
			t.Fatal(closeErr)
		}
		if disposeErr := w.discard(); disposeErr != nil {
			t.Fatal(disposeErr)
		}
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := ExerciseTemporaryQEMU(context.Background(), c); err != nil {
		t.Fatal(err)
	}
}
