//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"sync"
	"testing"

	"golang.org/x/sys/unix"
)

// Cancel immediately after the first sampled Err result. This deterministically
// models cancellation between the entry check and the next admission step.
type cancelAfterEntryContext struct {
	context.Context
	cancel context.CancelFunc
	once   sync.Once
}

type cancelAfterRead struct {
	reader io.Reader
	cancel context.CancelFunc
	reads  int
}

func (r *cancelAfterRead) Read(data []byte) (int, error) {
	n, err := r.reader.Read(data)
	r.reads++
	r.cancel()
	return n, err
}

func TestCaptureHashReaderStopsBetweenRealFileReads(t *testing.T) {
	owner, _ := captureFixture(t, "/usr/bin/printf", nil, bytes.Repeat([]byte{'x'}, MaxCaptureInput))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	observed := &cancelAfterRead{reader: io.NewSectionReader(owner.input, 0, owner.inputStat.Size), cancel: cancel}
	hash := sha256.New()
	count, err := io.Copy(hash, captureContextReader{ctx: ctx, reader: observed})
	if !errors.Is(err, context.Canceled) || count <= 0 || count >= owner.inputStat.Size || observed.reads != 1 {
		t.Fatal("hash continued after its first real-file read was canceled", count, observed.reads, err)
	}
	if offset, err := unix.Seek(int(owner.input.Fd()), 0, 1); err != nil || offset != 0 {
		t.Fatal("hash changed the shared input offset", offset, err)
	}
}

func TestCaptureDigestCancellationAndUnchangedControl(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, MaxCaptureInput)
	owner, _ := captureFixture(t, "/usr/bin/printf", nil, data)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	digest, err := captureDigestContext(ctx, owner.input, owner.inputStat, MaxCaptureInput)
	if !errors.Is(err, context.Canceled) || digest != [32]byte{} {
		t.Fatal("canceled hash published a digest", err)
	}
	digest, err = captureDigestContext(context.Background(), owner.input, owner.inputStat, MaxCaptureInput)
	if err != nil || digest != sha256.Sum256(data) {
		t.Fatal("unchanged real-file hash refused or differed", err)
	}
	if offset, err := unix.Seek(int(owner.input.Fd()), 0, 1); err != nil || offset != 0 {
		t.Fatal("digest changed the shared input offset", offset, err)
	}
}

// Used only by the synchronous digest helper: the third check is between
// chunks for a full-size input, or the final metadata fence for an empty one.
type cancelOnThirdHashCheck struct {
	context.Context
	cancel context.CancelFunc
	checks int
}

func (c *cancelOnThirdHashCheck) Err() error {
	c.checks++
	if c.checks == 3 {
		c.cancel()
	}
	return c.Context.Err()
}

func TestCaptureDigestCancellationDuringAndAfterReads(t *testing.T) {
	for _, size := range []int{0, MaxCaptureInput} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			owner, _ := captureFixture(t, "/usr/bin/printf", nil, bytes.Repeat([]byte{'x'}, size))
			parent, cancel := context.WithCancel(context.Background())
			defer cancel()
			ctx := &cancelOnThirdHashCheck{Context: parent, cancel: cancel}
			digest, err := captureDigestContext(ctx, owner.input, owner.inputStat, MaxCaptureInput)
			if !errors.Is(err, context.Canceled) || digest != [32]byte{} || ctx.checks != 3 {
				t.Fatal("partially or finally canceled hash published a digest", ctx.checks, err)
			}
		})
	}
}

func TestCaptureAdmissionCancellationDoesNotMaskObservedDrift(t *testing.T) {
	for _, valid := range []bool{true, false} {
		t.Run(fmt.Sprint(valid), func(t *testing.T) {
			owner, _ := captureFixture(t, "/usr/bin/printf", nil, []byte("fixture"))
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owner.fixtureInputsValid = func() bool {
				cancel()
				return valid
			}
			result, err := owner.Capture(ctx)
			want := error(context.Canceled)
			if !valid {
				want = ErrReviewRequired
			}
			if !errors.Is(err, want) || !zeroCapture(result) || owner.consumed || owner.current != nil || owner.review == valid {
				t.Fatal("cancellation masked drift or consumed an unstarted owner", err, owner.review)
			}
		})
	}
}

func TestCapturePostObservationCancellationDiscardsOutput(t *testing.T) {
	owner, _ := captureFixture(t, "/usr/bin/printf", []string{"%s", "must not be published"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	checks := 0
	owner.fixtureInputsValid = func() bool {
		checks++
		if checks == 2 {
			cancel()
		}
		return true
	}
	result, err := owner.Capture(ctx)
	if !errors.Is(err, context.Canceled) || !zeroCapture(result) || checks != 2 || !owner.consumed || !owner.review || owner.current != nil {
		t.Fatal("post-execution cancellation published output or lost ownership", checks, err)
	}
	if result, err := owner.Capture(context.Background()); !errors.Is(err, ErrReviewRequired) || !zeroCapture(result) {
		t.Fatal("canceled completed capture authorized retry", err)
	}
	if settled, err := owner.Settled(context.Background()); !settled || err != nil {
		t.Fatal("completed capture was not settled", err)
	}
}

func (c *cancelAfterEntryContext) Err() error {
	err := c.Context.Err()
	c.once.Do(c.cancel)
	return err
}

func TestCaptureCanceledAfterEntryDoesNotReadInputs(t *testing.T) {
	owner, path := captureFixture(t, "/usr/bin/printf", nil, []byte("synthetic regular input"))
	watch, err := unix.InotifyInit1(unix.IN_NONBLOCK | unix.IN_CLOEXEC)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(watch)
	if _, err := unix.InotifyAddWatch(watch, path, unix.IN_ACCESS); err != nil {
		t.Fatal(err)
	}
	// Prove this exact watch observes real reads, then drain that control event.
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	_, readErr := input.Read(one[:])
	closeErr := input.Close()
	var events [4096]byte
	if n, err := unix.Read(watch, events[:]); readErr != nil || closeErr != nil || err != nil || n == 0 {
		t.Fatal("read observation control failed", readErr, closeErr, err)
	}
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	ctx := &cancelAfterEntryContext{Context: parent, cancel: cancel}
	result, err := owner.Capture(ctx)
	if !errors.Is(err, context.Canceled) || !zeroCapture(result) {
		t.Fatal("entry cancellation published a result", err)
	}
	if n, err := unix.Read(watch, events[:]); !errors.Is(err, unix.EAGAIN) {
		t.Fatalf("canceled admission read the retained input: event bytes=%d err=%v", n, err)
	}
	if owner.consumed || owner.current != nil || owner.review {
		t.Fatal("pre-admission cancellation consumed or quarantined an unstarted owner")
	}
	if settled, err := owner.Settled(context.Background()); !settled || err != nil {
		t.Fatal("canceled admission created unsettled process ownership", err)
	}
}
