//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
)

func TestConfirmedNASOwnerPublishesThroughOriginalLeaseContract(t *testing.T) {
	dir, ctx := nasEvidenceFixture(t), context.Background()
	base, next := nasWriterPolicy(t, 2), nasWriterPolicy(t, 3)
	o, err := OpenConfirmedNASOwner(ctx, dir, evidenceInstallation, base)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	lease, err := o.Acquire(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := lease.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := o.Commit(ctx, 2, nasKillPolicy(3)); !errors.Is(err, ErrBusy) {
		t.Fatal("live claim permitted mutation", err)
	}
	if err := o.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("live claim permitted close", err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	candidate, err := nasKillCodec().Decode(bytes.NewReader(next))
	if err != nil {
		t.Fatal(err)
	}
	invalid := candidate
	invalid.Revision = 0
	if err := o.Commit(ctx, 2, invalid); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid candidate accepted", err)
	}
	if err := o.Commit(ctx, 1, candidate); !errors.Is(err, ErrConflict) {
		t.Fatal("stale publication accepted", err)
	}
	if err := o.Commit(ctx, 2, candidate); err != nil {
		t.Fatal("ordered publication failed", err)
	}
	if _, err := o.Acquire(ctx, 2); !errors.Is(err, ErrConflict) {
		t.Fatal("stale claim accepted", err)
	}
	for role, want := range map[string][]byte{"nas-services.json": next, ".nas-services.base": base} {
		got, err := os.ReadFile(filepath.Join(dir, role))
		if err != nil || !bytes.Equal(got, want) {
			t.Fatal("exact operation evidence differs", role, err)
		}
	}
	intent, a := os.ReadFile(filepath.Join(dir, ".nas-services.intent"))
	receipt, b := os.ReadFile(filepath.Join(dir, ".nas-services.receipt"))
	if errors.Join(a, b) != nil || naspolicyevidence.Inspect(evidenceInstallation, next, intent, receipt, true) != naspolicyevidence.MatchingLocalRecords {
		t.Fatal("local receipt does not match ordered operation")
	}
	value, err := o.Snapshot(ctx)
	if err != nil || value.Revision != 3 {
		t.Fatal("new policy unavailable", err)
	}
	value.FileServices.Shares.Shares[0].Name = "caller-owned-copy"
	fresh, err := o.Snapshot(ctx)
	if err != nil || fresh.FileServices.Shares.Shares[0].Name == "caller-owned-copy" {
		t.Fatal("snapshot aliases retained state", err)
	}
	copy := reflect.New(reflect.TypeOf(o).Elem())
	copy.Elem().Set(reflect.ValueOf(o).Elem())
	if _, err := copy.Interface().(*OwnedStore[naspolicy.Config]).Snapshot(ctx); !errors.Is(err, ErrInvalid) {
		t.Fatal("copied Owner accepted", err)
	}
}

func TestConfirmedNASOwnerDriftKeepsReviewAndOriginalClaims(t *testing.T) {
	dir, ctx := nasEvidenceFixture(t), context.Background()
	base := nasWriterPolicy(t, 2)
	o, err := OpenConfirmedNASOwner(ctx, dir, evidenceInstallation, base)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	lease, err := o.Acquire(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if err := os.WriteFile(filepath.Join(dir, "nas-services.json"), base, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := o.Snapshot(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("restored-content write cleared provenance", err)
	}
	if err := lease.Verify(ctx); !errors.Is(err, ErrReview) {
		t.Fatal("drifted consumer claim remained healthy", err)
	}
	if err := o.Commit(ctx, 2, nasKillPolicy(3)); !errors.Is(err, ErrReview) {
		t.Fatal("review permitted publication", err)
	}
	if err := o.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("review released outstanding consumer", err)
	}
	if other, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("review lost original root lock", err)
	}
}

func TestConfirmedNASOwnerRefusesUnconfirmedOrCanceledConstruction(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name string
		ctx  context.Context
		base []byte
		want error
	}{{"nil", nil, nasWriterPolicy(t, 2), ErrInvalid}, {"canceled", canceled, nasWriterPolicy(t, 2), context.Canceled}, {"stale", context.Background(), nasWriterPolicy(t, 1), ErrReview}} {
		t.Run(test.name, func(t *testing.T) {
			dir := nasEvidenceFixture(t)
			o, err := OpenConfirmedNASOwner(test.ctx, dir, evidenceInstallation, test.base)
			if o != nil || !errors.Is(err, test.want) {
				t.Fatal("invalid constructor admitted Owner", err)
			}
			current, err := os.ReadFile(filepath.Join(dir, "nas-services.json"))
			if err != nil || !bytes.Equal(current, nasWriterPolicy(t, 2)) {
				t.Fatal("constructor changed current policy", err)
			}
		})
	}
}
