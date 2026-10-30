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

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"golang.org/x/sys/unix"
)

func TestNASBootstrapTransfersOriginalLifetimeIntoOwner(t *testing.T) {
	ctx, dir := context.Background(), nasEvidenceFixture(t)
	b, err := OpenNASOwnerBootstrap(ctx, dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := b.Confirm(canceled, nasWriterPolicy(t, 2)); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled handoff admitted an owner", err)
	}
	copy := reflect.New(reflect.TypeOf(b).Elem())
	copy.Elem().Set(reflect.ValueOf(b).Elem())
	if _, err := copy.Interface().(*NASOwnerBootstrap).Confirm(ctx, nasWriterPolicy(t, 2)); !errors.Is(err, ErrInvalid) {
		t.Fatal("copied bootstrap retained authority", err)
	}
	if _, err := b.Confirm(ctx, nasWriterPolicy(t, 2)); !errors.Is(err, ErrInvalid) {
		t.Fatal("unobserved bootstrap admitted an owner", err)
	}
	// A duplicate keeps the original open-file-description flock alive even if
	// an implementation incorrectly closes its first FD and tries to reopen.
	fd, err := unix.FcntlInt(b.evidence.root.root.Fd(), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	alias := os.NewFile(uintptr(fd), "fixture-original-bootstrap-lock")
	defer alias.Close()
	observed, err := b.Observe(ctx)
	if err != nil || observed.Kind != naspolicyevidence.MatchingLocalRecords {
		t.Fatal("classification failed", err)
	}
	o, err := b.Confirm(ctx, nasWriterPolicy(t, 2))
	if err != nil {
		t.Fatal("confirmation did not retain the original root/lock/watch", err)
	}
	defer o.Close()
	if !errors.Is(b.Close(), ErrClosed) {
		t.Fatal("transferred bootstrap still has close authority")
	}
	if _, err := b.Observe(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal("transferred bootstrap remained observable", err)
	}
	if _, err := b.Confirm(ctx, nasWriterPolicy(t, 2)); !errors.Is(err, ErrClosed) {
		t.Fatal("bootstrap admitted a second owner", err)
	}
	lease, err := o.Acquire(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	defer lease.Release()
	if !errors.Is(o.Commit(ctx, 2, nasKillPolicy(3)), ErrBusy) {
		t.Fatal("handoff lost consumer exclusion")
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	candidate, err := nasKillCodec().Decode(bytes.NewReader(nasWriterPolicy(t, 3)))
	if err != nil {
		t.Fatal(err)
	}
	if err := o.Commit(ctx, 2, candidate); err != nil {
		t.Fatal("original writer could not publish", err)
	}
	if err := o.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
		t.Fatal("original flock was explicitly unlocked under its alias", err)
	}
	if err := alias.Close(); err != nil {
		t.Fatal(err)
	}
	a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if got, err := a.Observe(ctx); err != nil || got.Kind != naspolicyevidence.MatchingLocalRecords {
		t.Fatal("ordered receipt missing after original lifetime closed", err)
	}
}

func TestNASBootstrapRefusalsRetainEvidenceAndLock(t *testing.T) {
	for _, fault := range []string{"wrong-base", "restored-role", "pending"} {
		t.Run(fault, func(t *testing.T) {
			ctx, dir := context.Background(), nasEvidenceFixture(t)
			if fault == "pending" {
				if err := os.WriteFile(filepath.Join(dir, ".nas-services.pending"), []byte("uncertain"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			b, err := OpenNASOwnerBootstrap(ctx, dir, evidenceInstallation)
			if err != nil {
				t.Fatal(err)
			}
			defer b.Close()
			if _, err := b.Observe(ctx); err != nil {
				t.Fatal(err)
			}
			known := nasWriterPolicy(t, 2)
			if fault == "wrong-base" {
				known = nasWriterPolicy(t, 3)
			}
			if fault == "restored-role" {
				path := filepath.Join(dir, "nas-services.json")
				for _, data := range [][]byte{[]byte("{}"), nasWriterPolicy(t, 2)} {
					if err := os.WriteFile(path, data, 0600); err != nil {
						t.Fatal(err)
					}
				}
			}
			capture := func() map[string]string {
				out := map[string]string{}
				entries, err := os.ReadDir(dir)
				if err != nil {
					t.Fatal(err)
				}
				for _, entry := range entries {
					data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
					if err != nil {
						t.Fatal(err)
					}
					out[entry.Name()] = string(data)
				}
				return out
			}
			before := capture()
			for i := 0; i < 2; i++ {
				if owner, err := b.Confirm(ctx, known); owner != nil || !errors.Is(err, ErrReview) {
					t.Fatal("uncertain evidence admitted or retried", err)
				}
			}
			if !reflect.DeepEqual(before, capture()) {
				t.Fatal("refusal rewrote or retired evidence")
			}
			if other, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
				if other != nil {
					other.Close()
				}
				t.Fatal("refusal released original exclusion", err)
			}
		})
	}
}
