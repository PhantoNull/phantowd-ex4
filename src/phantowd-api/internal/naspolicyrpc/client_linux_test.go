//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicyrpc

import (
	"context"
	"errors"
	"net"
	"os"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

func TestClientUncertainReplyRefusesFurtherOperations(t *testing.T) {
	a, b := net.Pipe()
	c := newClient(a) // Transport failure seam; root peer is qualified in QEMU.
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.Snapshot(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer b.Close()
		if _, err := readFrame(b); err != nil {
			return
		}
		_ = writeFrame(b, message(0, 0, []byte("{}")))
	}()
	if got, err := c.Snapshot(context.Background()); !errors.Is(err, naspolicystore.ErrReview) || got.Revision != 0 {
		t.Fatal(got, err)
	}
	<-done
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, naspolicystore.ErrReview) {
		t.Fatal("uncertain channel reused", err)
	}
	if c.Close() != nil || c.Close() != nil {
		t.Fatal("channel disposal failed")
	}
}

func TestClientRejectsNonRootPeerBeforeIO(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("non-root peer control runs in the pinned UID1000 host lane")
	}
	a, _ := pair(t)
	if _, err := NewClient(a); !errors.Is(err, naspolicystore.ErrInvalid) {
		t.Fatal("non-root server admitted", err)
	}
}

func TestClientCanceledExchangeRefusesReuse(t *testing.T) {
	a, b := net.Pipe()
	defer b.Close()
	c := newClient(a)
	defer c.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan struct{})
	go func() { _, _ = readFrame(b); cancel(); close(done) }()
	if _, err := c.Snapshot(ctx); !errors.Is(err, naspolicystore.ErrReview) {
		t.Fatal(err)
	}
	if _, err := c.Snapshot(context.Background()); !errors.Is(err, naspolicystore.ErrReview) {
		t.Fatal("canceled exchange reused", err)
	}
	<-done
}
