//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// Kernel-independent refusal checks must execute even where the actual native
// statx-positive lifecycle tests deliberately skip. No forged syscall identity.
func TestBackingUseClaimsCannotBeSerializedOrReconstructed(t *testing.T) {
	for _, value := range []any{newBackingUseOwner(), backingUseOwner{}, &backingUseLease{}, backingUseLease{}} {
		if data, err := json.Marshal(value); !errors.Is(err, ErrUnavailable) || len(data) != 0 {
			t.Fatal("private use claim serialized", err)
		}
	}
	var authority backingUseOwner
	var lease backingUseLease
	for _, value := range []any{&authority, &lease} {
		if err := json.Unmarshal([]byte(`{"source":{},"objects":[{"inode":1}]}`), value); !errors.Is(err, ErrUnavailable) {
			t.Fatal("serialized input reconstructed a private claim", err)
		}
	}
	if authority.entries != nil || lease.source != nil || lease.consumer != nil || len(lease.objects) != 0 {
		t.Fatal("failed decoding changed zero authority")
	}
}

func TestBackingUseUninitializedCloseRefusesAndEmptyCloseIsIdempotent(t *testing.T) {
	var uninitialized backingUseOwner
	if !errors.Is(uninitialized.close(), ErrInvalid) {
		t.Fatal("uninitialized authority accepted close")
	}
	empty := newBackingUseOwner()
	if err := empty.close(); err != nil {
		t.Fatal(err)
	}
	if err := empty.close(); err != nil {
		t.Fatal("verified empty close not idempotent", err)
	}
}

// Actual O_PATH/statx and separate RW descriptions on native disposable files;
// not a qualified mount. The mandatory ARMv5 fixture uses a real mount Owner.
func useInput(t *testing.T, r *testRoot, name string) (*Pin, *os.File) {
	t.Helper()
	p := pinned(t, r, name)
	fd, err := unix.Open(filepath.Join(r.path, name), unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f := os.NewFile(uintptr(fd), "native-use-input")
	t.Cleanup(func() { _ = f.Close() })
	return p, f
}

func TestBackingUseConcurrentIndependentConsumersHaveOneWinner(t *testing.T) {
	r := nativeRoot(t)
	backing(t, filepath.Join(r.path, "file"))
	uses := newBackingUseOwner()
	for round := 0; round < 16; round++ {
		p1, f1 := useInput(t, r, "file")
		p2, f2 := useInput(t, r, "file")
		type admission struct {
			owner *writableOwner
			err   error
		}
		results := make(chan admission, 2)
		start := make(chan struct{})
		for _, input := range []targetBacking{{pin: p1, file: f1}, {pin: p2, file: f2}} {
			go func(input targetBacking) {
				<-start
				o, err := newWritableOwner(input.pin, input.file, &lifecycleBackend{}, uses)
				results <- admission{o, err}
			}(input)
		}
		close(start)
		wins, conflicts := 0, 0
		var owners []*writableOwner
		// Join both admissions before releasing either winner.
		for range 2 {
			result := <-results
			if result.owner != nil && result.err == nil {
				wins++
				owners = append(owners, result.owner)
			}
			if result.owner == nil && errors.Is(result.err, ErrBusy) {
				conflicts++
			}
		}
		for _, owner := range owners {
			if err := owner.close(); err != nil {
				t.Fatal(err)
			}
		}
		if wins != 1 || conflicts != 1 {
			t.Fatal("concurrent admission was not exclusive", wins, conflicts)
		}
	}
	if err := uses.close(); err != nil {
		t.Fatal(err)
	}
}

func TestBackingUseUncertainStopKeepsReservationWithoutRetry(t *testing.T) {
	r := nativeRoot(t)
	backing(t, filepath.Join(r.path, "file"))
	p, f := useInput(t, r, "file")
	p2, f2 := useInput(t, r, "file")
	uses := newBackingUseOwner()
	b := &lifecycleBackend{stopError: ErrUnavailable}
	o, err := newWritableOwner(p, f, b, uses)
	if err != nil {
		t.Fatal(err)
	}
	// Independent disposal of this synthetic boundary, never product recovery.
	t.Cleanup(func() {
		b.active = false
		if err := o.releaseLocked(); err != nil {
			t.Error(err)
		}
		if err := uses.close(); err != nil {
			t.Error(err)
		}
	})
	ctx := context.Background()
	if err := o.start(ctx); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(o.stop(ctx), ErrReview) {
		t.Fatal("uncertain stop accepted")
	}
	if other, err := newWritableOwner(p2, f2, &lifecycleBackend{}, uses); other != nil || !errors.Is(err, ErrBusy) {
		if other != nil {
			_ = other.close()
		}
		t.Fatal("uncertain stop freed backing object", err)
	}
	if !errors.Is(uses.close(), ErrBusy) || !errors.Is(o.stop(ctx), ErrReview) || !errors.Is(o.close(), ErrReview) || b.stopCalls != 1 {
		t.Fatal("uncertain reservation released or teardown retried")
	}
}

func TestBackingUseIndependentOpenRefusalAndVerifiedReuse(t *testing.T) {
	r := nativeRoot(t)
	backing(t, filepath.Join(r.path, "file"))
	p, f := useInput(t, r, "file")
	p2, f2 := useInput(t, r, "file")
	uses := newBackingUseOwner()
	o, err := newWritableOwner(p, f, &lifecycleBackend{}, uses)
	if err != nil {
		t.Fatal(err)
	}
	if second, err := newWritableOwner(p2, f2, &lifecycleBackend{}, uses); second != nil || !errors.Is(err, ErrBusy) {
		t.Fatal("independent description admitted the held object", err)
	}
	if p2.consumer != nil {
		t.Fatal("refusal consumed caller Pin")
	}
	if _, err := f2.Stat(); err != nil {
		t.Fatal("refusal closed caller descriptor", err)
	}
	if !errors.Is(uses.close(), ErrBusy) {
		t.Fatal("authority closed with a prepared consumer")
	}
	if err := o.close(); err != nil {
		t.Fatal(err)
	}
	second, err := newWritableOwner(p2, f2, &lifecycleBackend{}, uses)
	if err != nil {
		t.Fatal("verified whole closure did not permit reuse", err)
	}
	if err := second.close(); err != nil {
		t.Fatal(err)
	}
	if err := uses.close(); err != nil {
		t.Fatal(err)
	}
}
