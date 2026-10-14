//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

func TestBootstrapAuthorityRetainsOneLockAcrossFreshReadOnlyObservations(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, nasKillPolicy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	a, err := OpenBootstrapAuthorityWithCodec(ctx, dir, nasKillCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	for range 20 {
		got, err := a.Observe(ctx)
		if err != nil || got != (BootstrapObservation{Kind: BootstrapValidCurrentPolicy, Revision: 1}) {
			t.Fatal("original observation unavailable", got, err)
		}
		if other, err := OpenWithCodec(dir, nasKillCodec()); !errors.Is(err, ErrBusy) {
			if other != nil {
				other.Close()
			}
			t.Fatal("authority dropped original lock between reads", err)
		}
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal("verified close not idempotent", err)
	}
	if got, err := a.Observe(ctx); !errors.Is(err, ErrClosed) || got != (BootstrapObservation{}) {
		t.Fatal("closed authority admitted observation", got, err)
	}
	s, err = OpenWithCodec(dir, nasKillCodec())
	if err != nil {
		t.Fatal("verified close did not release lock", err)
	}
	defer s.Close()
}

func TestBootstrapAuthorityWritableLifetimeDriftKeepsReviewAndLockWithUnchangedMetadata(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	a, err := OpenBootstrapAuthorityWithCodec(context.Background(), dir, shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	name := filepath.Join(dir, currentName)
	var before, after unix.Stat_t
	if unix.Stat(name, &before) != nil {
		t.Fatal("original metadata")
	}
	w, err := os.OpenFile(name, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if unix.Stat(name, &after) != nil || before != after {
		t.Fatal("fault unexpectedly altered metadata")
	}
	for range 10 {
		if got, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) || got != (BootstrapObservation{}) {
			t.Fatal("restored/unchanged input bypassed review", got, err)
		}
		if other, err := Open(dir); !errors.Is(err, ErrBusy) {
			if other != nil {
				other.Close()
			}
			t.Fatal("review released original lock", err)
		}
	}
}

func TestBootstrapAuthorityCanceledReadRetainsReviewButPreworkCancelHasNoEffects(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	codec := shareCodec()
	decode := codec.Decode
	codec.Decode = func(r io.Reader) (shareconfig.Config, error) { v, err := decode(r); cancel(); return v, err }
	a, err := OpenBootstrapAuthorityWithCodec(context.Background(), dir, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if got, err := a.Observe(canceled); !errors.Is(err, context.Canceled) || got != (BootstrapObservation{}) {
		t.Fatal("prework cancellation admitted observation", got, err)
	}
	if got, err := a.Observe(ctx); !errors.Is(err, ErrReview) || !errors.Is(err, context.Canceled) || got != (BootstrapObservation{}) {
		t.Fatal("in-flight cancellation not retained", got, err)
	}
	if got, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) || got != (BootstrapObservation{}) {
		t.Fatal("canceled read allowed retry", got, err)
	}
	if other, err := Open(dir); !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("cancellation dropped lock", err)
	}
}

func TestBootstrapAuthorityRejectsCopiesSerializationAndInvalidConstruction(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	a, err := OpenBootstrapAuthorityWithCodec(context.Background(), dir, shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	copy := reflect.New(reflect.TypeOf(a).Elem())
	copy.Elem().Set(reflect.ValueOf(a).Elem()) // Quiescent identity-refusal probe only.
	for _, bad := range []*BootstrapAuthority[shareconfig.Config]{nil, {}, copy.Interface().(*BootstrapAuthority[shareconfig.Config])} {
		if got, err := bad.Observe(context.Background()); !errors.Is(err, ErrInvalid) || got != (BootstrapObservation{}) {
			t.Fatal("unissued/copied authority admitted read", got, err)
		}
		if err := bad.Close(); !errors.Is(err, ErrInvalid) {
			t.Fatal("copied authority acquired disposal", err)
		}
	}
	if _, err := json.Marshal(a); !errors.Is(err, ErrInvalid) {
		t.Fatal("authority serialized", err)
	}
	if err := json.Unmarshal([]byte("{}"), a); !errors.Is(err, ErrInvalid) {
		t.Fatal("authority deserialized", err)
	}
	if _, err := a.Observe(context.Background()); err != nil {
		t.Fatal("refusal affected original", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := OpenBootstrapAuthorityWithCodec(ctx, dir, shareCodec()); got != nil || !errors.Is(err, context.Canceled) {
		t.Fatal("canceled constructor collected references", err)
	}
}

func TestBootstrapAuthorityUncertainCloseRetainsUnattemptedRootWithoutRetry(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	a, err := OpenBootstrapAuthorityWithCodec(context.Background(), dir, shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	// Test-only premature descriptor closure. No file creation/open is allowed
	// between this close and the owner's first Close, to avoid a reuse probe.
	if err := unix.Close(a.watch); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); !errors.Is(err, ErrReview) {
		t.Fatal("uncertain close declared healthy", err)
	}
	defer a.root.Close() // Independent fixture disposal after characterization.
	for range 3 {
		if err := a.Close(); !errors.Is(err, ErrReview) {
			t.Fatal("uncertain descriptor close retried", err)
		}
		if other, err := Open(dir); !errors.Is(err, ErrBusy) {
			if other != nil {
				other.Close()
			}
			t.Fatal("unattempted root released", err)
		}
		if got, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) || got != (BootstrapObservation{}) {
			t.Fatal("partial close admitted observation", got, err)
		}
	}
}
