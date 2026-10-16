//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"bytes"
	"context"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

// Called only for a fresh layout inside ExerciseTemporaryQEMU's checked tmpfs.
// This is a Store prerequisite, NOT an intent/policy/receipt transaction, new
// admission path, persistent state namespace or physical durability test.
func exerciseAnchoredStore(ctx context.Context, root string, candidate []byte, next naspolicy.Config) (result error) {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	parent, err := os.Open(root)
	if err != nil {
		return ErrIO
	}
	defer func() {
		if parent.Close() != nil {
			result = ErrReview
		}
	}()
	codec := revisionstore.Codec[naspolicy.Config]{
		CurrentName: "nas-services.json", PendingName: ".nas-services.pending",
		MaxBytes: naspolicy.MaxInputBytes, Decode: naspolicy.Decode, Validate: naspolicy.Config.Validate,
		Revision: func(c naspolicy.Config) uint64 { return c.Revision },
	}
	s, err := revisionstore.OpenAnchoredWithCodec(parent, "policy", codec)
	if err != nil {
		return err
	}
	defer func() {
		if s.Close() != nil {
			result = ErrReview
		}
	}()
	other, err := naspolicystore.Open(filepath.Join(root, "policy"))
	if other != nil {
		_ = other.Close()
		return ErrReview
	}
	if err != naspolicystore.ErrBusy {
		return ErrReview
	}
	if err := s.Commit(next.Revision-1, next); err != nil {
		return err
	}
	v, raw, err := s.LoadExact()
	if err != nil || v.Revision != next.Revision || !bytes.Equal(raw, candidate) {
		return ErrReview
	}
	// Introduce unresolved evidence AFTER construction. The Store must never
	// discard it and restoration must not revive this uncertain instance.
	pending := filepath.Join(root, "policy", codec.PendingName)
	if os.WriteFile(pending, []byte("synthetic-pending"), 0600) != nil {
		return ErrIO
	}
	if v, raw, err := s.LoadExact(); err != revisionstore.ErrUncertain || raw != nil || v.Revision != 0 {
		return ErrReview
	}
	if raw, err := os.ReadFile(pending); err != nil || string(raw) != "synthetic-pending" {
		return ErrReview
	}
	// Fixture-only restoration; never performed by Store or product recovery.
	if os.Remove(pending) != nil {
		return ErrIO
	}
	if _, err := s.Load(); err != revisionstore.ErrUncertain || s.Commit(next.Revision-1, next) != revisionstore.ErrUncertain {
		return ErrReview
	}
	if raw, err := os.ReadFile(filepath.Join(root, "policy", codec.CurrentName)); err != nil || !bytes.Equal(raw, candidate) {
		return ErrReview
	}
	return ctx.Err()
}
