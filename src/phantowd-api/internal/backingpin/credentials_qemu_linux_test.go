//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
)

type credentialLifecycleBackend struct {
	*lifecycleBackend
	peers          []iscsicredentials.Credential
	prepareCalls   int
	prepareError   error
	stopWithSecret bool
	onPrepare      func()
}

func (b *credentialLifecycleBackend) PrepareCredentials(_ context.Context, peers []iscsicredentials.Credential) error {
	b.prepareCalls++
	b.peers = append([]iscsicredentials.Credential(nil), peers...)
	if b.onPrepare != nil {
		b.onPrepare()
	}
	return b.prepareError
}
func (b *credentialLifecycleBackend) stop(ctx context.Context) error {
	if len(b.peers) > 0 {
		_, err := b.peers[0].Incoming.WriteTo(io.Discard)
		b.stopWithSecret = err == nil
	}
	return b.lifecycleBackend.stop(ctx)
}

// Native state-machine seam only; no real mounted descriptor qualification.
func TestCredentialBoundLifetimeOrderingAndFailureFences(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("credential positive requires isolated root Linux/QEMU")
	}
	for _, kind := range []string{"normal", "drift", "uncertain", "prepare", "prepare-uncertain", "post-prepare-drift", "file-close", "pin-close", "pre-start-drift"} {
		t.Run(kind, func(t *testing.T) {
			o, base := lifecycleOwner(t)
			backend := &credentialLifecycleBackend{lifecycleBackend: base}
			o.backend = backend
			policy, _ := lifecyclePolicyOwner(t, o)
			dir := filepath.Join(t.TempDir(), "vault")
			secrets, err := iscsicredentials.OpenQEMUFixture(dir)
			if err != nil {
				t.Fatal(err)
			}
			ctx := context.Background()
			bundle, err := secrets.Acquire(ctx, 1, fixtureBackingPolicy(1, "synthetic/data"), "fixture-target", backend)
			if err != nil {
				t.Fatal(err)
			}
			o.credentials = bundle
			t.Cleanup(func() {
				_ = bundle.Release()
				if err := secrets.Close(); err != nil {
					t.Error(err)
				}
			})
			if kind == "pre-start-drift" {
				if err := mutateFixtureDocument(dir, "chap-secrets.json"); err != nil {
					t.Fatal(err)
				}
			}
			if strings.HasPrefix(kind, "prepare") {
				backend.prepareError = ErrUnavailable
			}
			if kind == "prepare-uncertain" || kind == "uncertain" {
				base.stopError = ErrReview
			}
			if kind == "post-prepare-drift" {
				backend.onPrepare = func() {
					if err := mutateFixtureDocument(dir, "chap-secrets.json"); err != nil {
						t.Fatal(err)
					}
				}
			}
			startErr := o.start(ctx)
			if strings.HasPrefix(kind, "prepare") || kind == "post-prepare-drift" || kind == "pre-start-drift" {
				if !errors.Is(startErr, ErrReview) || base.startCalls != 0 {
					t.Fatal("credential preparation failed open")
				}
				if kind != "pre-start-drift" && (base.stopCalls != 1 || !backend.stopWithSecret) {
					t.Fatal("prepare uncertainty bypassed teardown")
				}
			} else {
				if startErr != nil {
					t.Fatal(startErr)
				}
				switch kind {
				case "normal":
					if err := o.stop(ctx); err != nil {
						t.Fatal(err)
					}
				case "drift", "uncertain":
					if err := mutateFixtureDocument(dir, "chap-secrets.json"); err != nil {
						t.Fatal(err)
					}
					if !errors.Is(o.observe(ctx), ErrReview) {
						t.Fatal("credential drift not review")
					}
				case "file-close":
					_ = o.file.Close()
					if !errors.Is(o.stop(ctx), ErrReview) {
						t.Fatal("close uncertainty ignored")
					}
				case "pin-close":
					meta, err := os.CreateTemp(t.TempDir(), "metadata-")
					if err != nil {
						t.Fatal(err)
					}
					_ = meta.Close()
					o.pin.file = meta
					if !errors.Is(o.stop(ctx), ErrReview) {
						t.Fatal("pin uncertainty ignored")
					}
				}
			}
			retained := kind == "uncertain" || kind == "prepare-uncertain" || kind == "file-close" || kind == "pin-close"
			if retained {
				if o.released || o.credentials == nil || !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) {
					t.Fatal("uncertainty released secret claim")
				}
				if _, err := bundlePeerSecret(backend).WriteTo(io.Discard); err != nil {
					t.Fatal("uncertainty wiped borrow")
				}
			} else {
				if !o.released || o.credentials != nil {
					t.Fatal("verified release retained credentials")
				}
				if len(backend.peers) > 0 {
					if _, err := backend.peers[0].Incoming.WriteTo(io.Discard); !errors.Is(err, iscsicredentials.ErrClosed) {
						t.Fatal("released borrow usable")
					}
				}
			}
			if kind != "normal" {
				stops, prepares := base.stopCalls, backend.prepareCalls
				for _, op := range []func() error{func() error { return o.start(ctx) }, func() error { return o.stop(ctx) }, o.close} {
					if !errors.Is(op(), ErrReview) {
						t.Fatal("review bypass")
					}
				}
				if base.stopCalls != stops || backend.prepareCalls != prepares {
					t.Fatal("review retried")
				}
			}
			_ = policy
			for _, value := range []any{o, writableOwner{credentials: bundle}} {
				if data, err := json.Marshal(value); err == nil || len(data) != 0 {
					t.Fatal("credential owner serialized")
				}
				if !strings.Contains(fmt.Sprintf("%#v", value), "private backing owner") {
					t.Fatal("credential owner not text-redacted")
				}
			}
		})
	}
}
func bundlePeerSecret(b *credentialLifecycleBackend) iscsicredentials.Secret {
	if len(b.peers) == 0 {
		return iscsicredentials.Secret{}
	}
	return b.peers[0].Incoming
}
