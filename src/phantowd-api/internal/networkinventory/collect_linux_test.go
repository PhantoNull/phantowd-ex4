// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestActualUnprivilegedKernelCollectionAndRecheck(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 8 {
		o, err := Collect(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		s, err := o.Summary()
		if err != nil || s.Interfaces < 1 || s.Routes < 1 || s.Rules < 1 || s.UnresolvedRoutes > s.Routes || s.UnresolvedRules > s.Rules {
			t.Fatal("missing interfaces")
		}
		if err := Recheck(context.Background(), o); err != nil {
			t.Fatal(err)
		}
		// Wrong namespace evidence is refused without a public forgeable token.
		o.namespace.inode++
		if err := Recheck(context.Background(), o); err != ErrChanged {
			t.Fatal("namespace change accepted")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("descriptor count changed")
	}
}

func TestKernelCollectorCancellationAndDeadline(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, ctx := range []context.Context{nil, ctx} {
		if o, e := Collect(ctx); o != nil || e != ErrUnavailable {
			t.Fatal("invalid context accepted")
		}
	}
	r := &kernelReader{fd: -1, deadline: time.Now().Add(-time.Second)}
	if r.available(context.Background()) || r.available(nil) {
		t.Fatal("expired/nil budget admitted")
	}
	if _, e := r.query(context.Background(), 18, 16, 0); e != ErrUnavailable {
		t.Fatal("expired query accepted")
	}
	r.deadline = time.Now().Add(time.Second)
	if !r.available(context.Background()) || r.available(ctx) {
		t.Fatal("socket budget/cancellation gate")
	}
}
