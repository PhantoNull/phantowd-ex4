// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package passwordhash

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestKDFSerializesWork(t *testing.T) {
	const workers = 8
	ready := make(chan struct{}, workers)
	entered := make(chan struct{}, workers)
	release := make(chan struct{})
	var active, peak atomic.Int32
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			ready <- struct{}{}
			if err := withKDFSlot(context.Background(), func() error {
				current := active.Add(1)
				for observed := peak.Load(); current > observed; observed = peak.Load() {
					if peak.CompareAndSwap(observed, current) {
						break
					}
				}
				entered <- struct{}{}
				<-release
				active.Add(-1)
				return nil
			}); err != nil {
				t.Errorf("work failed: %v", err)
			}
		}()
	}
	for range workers {
		select {
		case <-ready:
		case <-time.After(2 * time.Second):
			t.Fatal("worker did not reach the limiter")
		}
	}
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		t.Fatal("first worker did not enter the limiter")
	}
	if got := len(entered); got != 0 {
		t.Fatalf("multiple workers entered while the first held the slot: queued=%d", got)
	}
	close(release)
	wait.Wait()
	if got := peak.Load(); got != 1 {
		t.Fatalf("peak concurrent KDF work=%d, want 1", got)
	}
}

func TestKDFAllowsWaitingCallerToCancel(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	firstDone := make(chan error, 1)
	go func() {
		firstDone <- withKDFSlot(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered

	ctx, cancel := context.WithCancel(context.Background())
	started := make(chan struct{})
	secondDone := make(chan error, 1)
	callbackRan := atomic.Bool{}
	go func() {
		close(started)
		secondDone <- withKDFSlot(ctx, func() error {
			callbackRan.Store(true)
			return nil
		})
	}()
	<-started
	cancel()
	select {
	case err := <-secondDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiting caller returned %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waiting caller did not cancel")
	}
	if callbackRan.Load() {
		t.Fatal("cancelled caller entered KDF work")
	}
	close(release)
	if err := <-firstDone; err != nil {
		t.Fatalf("first work failed: %v", err)
	}
}

func TestKDFRejectsInvalidVerifierBeforeTakingSlot(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	holderDone := make(chan error, 1)
	go func() {
		holderDone <- withKDFSlot(context.Background(), func() error {
			close(entered)
			<-release
			return nil
		})
	}()
	<-entered
	invalidDone := make(chan error, 1)
	go func() {
		_, err := Verify(context.Background(), []byte("password"), "invalid")
		invalidDone <- err
	}()
	select {
	case err := <-invalidDone:
		if err == nil {
			t.Fatal("invalid verifier accepted")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("invalid verifier waited for the KDF work slot")
	}
	close(release)
	if err := <-holderDone; err != nil {
		t.Fatalf("slot holder failed: %v", err)
	}
}
