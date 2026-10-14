//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func pendingTCPPairRowsQEMU() []pendingTCPSocketQEMU {
	client := pendingTCPSocketQEMU{local: netip.MustParseAddrPort("127.0.0.1:30001"),
		peer: netip.MustParseAddrPort("127.0.0.1:1445"), inode: 11, cookie: 101, uid: 65534}
	server := pendingTCPSocketQEMU{local: client.peer, peer: client.local, inode: 12, cookie: 102}
	peer := client
	peer.local, peer.inode, peer.cookie = netip.MustParseAddrPort("127.0.0.1:30002"), 21, 201
	accepted := server
	accepted.peer, accepted.inode, accepted.cookie = peer.local, 22, 202
	return []pendingTCPSocketQEMU{accepted, client, peer, server}
}

func TestPendingTCPPairSelectsExactReciprocalObjects(t *testing.T) {
	rows := pendingTCPPairRowsQEMU()
	before := slices.Clone(rows)
	first, err := matchPendingTCPPairQEMU(context.Background(), rows, 11, 12)
	if err != nil || first.client != rows[1] || first.server != rows[3] {
		t.Fatal("original pair unavailable", err)
	}
	second, err := matchPendingTCPPairQEMU(context.Background(), rows, 21, 22)
	if err != nil || second.client != rows[2] || second.server != rows[0] || first == second {
		t.Fatal("same-UID/same-server connections conflated", err)
	}
	if !slices.Equal(rows, before) {
		t.Fatal("comparison mutated dump")
	}
	for i := len(rows); i < maxPendingTCPSocketsQEMU; i++ {
		row := before[1]
		row.local = netip.AddrPortFrom(row.local.Addr(), uint16(20000+i))
		row.inode, row.cookie = uint32(1000+i), uint64(1000+i)
		rows = append(rows, row)
	}
	if atLimit, err := matchPendingTCPPairQEMU(context.Background(), rows, 11, 12); err != nil || atLimit != first {
		t.Fatal("exact bounded row limit rejected", err)
	}
	rows[1].cookie++
	if first.client.cookie != 101 {
		t.Fatal("result aliases caller")
	}
}

func TestPendingTCPPairRefusesAmbiguousMissingAndForeignObservations(t *testing.T) {
	for name, change := range map[string]func([]pendingTCPSocketQEMU) []pendingTCPSocketQEMU{
		"empty":            func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { return nil },
		"missing original": func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { return r[:3] },
		"wrong reciprocal": func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { r[3].peer = r[2].local; return r },
		"foreign address": func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU {
			r[1].local = netip.MustParseAddrPort("192.0.2.1:30001")
			r[3].peer = r[1].local
			return r
		},
		"wrong service": func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU {
			r[3].local = netip.MustParseAddrPort("127.0.0.1:1446")
			r[1].peer = r[3].local
			return r
		},
		"self connection": func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU {
			r[1].local = r[3].local
			r[3].peer = r[1].local
			return r
		},
		"bound interface":       func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { r[1].interfaceID = 7; return r },
		"duplicate inode":       func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { r[2].inode = r[1].inode; return r },
		"duplicate cookie":      func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { r[2].cookie = r[1].cookie; return r },
		"duplicate tuple":       func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { r[2].local = r[1].local; return r },
		"invalid unrelated row": func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { r[0].inode = 0; return r },
		"missing cookie":        func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU { r[0].cookie = ^uint64(0); return r },
		"oversized": func(r []pendingTCPSocketQEMU) []pendingTCPSocketQEMU {
			return make([]pendingTCPSocketQEMU, maxPendingTCPSocketsQEMU+1)
		},
	} {
		t.Run(name, func(t *testing.T) {
			pair, err := matchPendingTCPPairQEMU(context.Background(), change(pendingTCPPairRowsQEMU()), 11, 12)
			if !errors.Is(err, ErrUnavailable) || pair != (pendingTCPPairQEMU{}) {
				t.Fatal("ambiguous observations became a connection", err)
			}
		})
	}
	for _, ids := range [][2]uint32{{0, 12}, {11, 0}, {11, 11}, {99, 12}, {12, 11}, {11, 22}} {
		if pair, err := matchPendingTCPPairQEMU(context.Background(), pendingTCPPairRowsQEMU(), ids[0], ids[1]); !errors.Is(err, ErrUnavailable) || pair != (pendingTCPPairQEMU{}) {
			t.Fatal("foreign/reversed/zero object selection accepted", ids, err)
		}
	}
}

func TestPendingTCPPairActualKernelDistinctOriginalsAndClosure(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1445})
	if err != nil {
		t.Fatal("fixed disposable loopback fixture unavailable", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	clientA, serverA := pendingTCPFixturePairAtQEMU(t, listener)
	clientB, serverB := pendingTCPFixturePairAtQEMU(t, listener)
	wantA := pendingTCPPairQEMU{client: pendingTCPFixtureDescriptorQEMU(t, clientA), server: pendingTCPFixtureDescriptorQEMU(t, serverA)}
	wantB := pendingTCPPairQEMU{client: pendingTCPFixtureDescriptorQEMU(t, clientB), server: pendingTCPFixtureDescriptorQEMU(t, serverB)}
	before := pendingTCPFixtureFDCountQEMU(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	for range 2 {
		rows, err := pendingTCPKernelFixtureQEMU(ctx)
		if err != nil {
			t.Fatal(err)
		}
		for _, want := range []pendingTCPPairQEMU{wantA, wantB} {
			got, err := matchPendingTCPPairQEMU(ctx, rows, want.client.inode, want.server.inode)
			if err != nil || got != want {
				t.Fatal("real pair differs from independent original descriptors", err)
			}
		}
		if got, err := matchPendingTCPPairQEMU(ctx, rows, wantA.client.inode, wantB.server.inode); err == nil || got != (pendingTCPPairQEMU{}) {
			t.Fatal("same-UID/server cross-pair accepted")
		}
	}
	if after := pendingTCPFixtureFDCountQEMU(t); after != before {
		t.Fatal("pair observations leaked descriptors", before, after)
	}
	if err := errors.Join(clientA.Close(), serverA.Close()); err != nil {
		t.Fatal(err)
	}
	rows, err := pendingTCPKernelFixtureQEMU(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := matchPendingTCPPairQEMU(ctx, rows, wantA.client.inode, wantA.server.inode); err == nil || got != (pendingTCPPairQEMU{}) {
		t.Fatal("closed original pair admitted")
	}
	if got, err := matchPendingTCPPairQEMU(ctx, rows, wantB.client.inode, wantB.server.inode); err != nil || got != wantB {
		t.Fatal("peer pair changed after original closure", err)
	}
}

type pendingPairCancelAtCheckQEMU struct {
	context.Context
	checks int
}

func (c *pendingPairCancelAtCheckQEMU) Err() error {
	c.checks--
	if c.checks <= 0 {
		return context.Canceled
	}
	return nil
}

func TestPendingTCPPairCancellationAndContinuity(t *testing.T) {
	if pair, err := matchPendingTCPPairQEMU(nil, pendingTCPPairRowsQEMU(), 11, 12); !errors.Is(err, ErrInvalid) || pair != (pendingTCPPairQEMU{}) {
		t.Fatal("nil context accepted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if pair, err := matchPendingTCPPairQEMU(ctx, pendingTCPPairRowsQEMU(), 11, 12); !errors.Is(err, context.Canceled) || pair != (pendingTCPPairQEMU{}) {
		t.Fatal("cancellation exposed result", err)
	}
	expired, expire := context.WithDeadline(context.Background(), time.Unix(1, 0))
	defer expire()
	if pair, err := matchPendingTCPPairQEMU(expired, pendingTCPPairRowsQEMU(), 11, 12); !errors.Is(err, context.DeadlineExceeded) || pair != (pendingTCPPairQEMU{}) {
		t.Fatal("expiry exposed result", err)
	}
	// Admission + four rows complete; cancellation at final publication must
	// discard both fully selected identities. This is a deterministic fence,
	// not a claim of arbitrary kernel-receive cancellation coverage.
	final := &pendingPairCancelAtCheckQEMU{Context: context.Background(), checks: 6}
	if pair, err := matchPendingTCPPairQEMU(final, pendingTCPPairRowsQEMU(), 11, 12); !errors.Is(err, context.Canceled) || pair != (pendingTCPPairQEMU{}) {
		t.Fatal("final cancellation published selected identities", err)
	}
	original, err := matchPendingTCPPairQEMU(context.Background(), pendingTCPPairRowsQEMU(), 11, 12)
	if err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func([]pendingTCPSocketQEMU){
		"client cookie":    func(r []pendingTCPSocketQEMU) { r[1].cookie += 10 },
		"server cookie":    func(r []pendingTCPSocketQEMU) { r[3].cookie += 10 },
		"client principal": func(r []pendingTCPSocketQEMU) { r[1].uid++ },
		"server principal": func(r []pendingTCPSocketQEMU) { r[3].uid++ },
		"reciprocal endpoints": func(r []pendingTCPSocketQEMU) {
			r[1].local = netip.MustParseAddrPort("127.0.0.1:30003")
			r[3].peer = r[1].local
		},
	} {
		t.Run(name, func(t *testing.T) {
			rows := pendingTCPPairRowsQEMU()
			change(rows)
			current, err := matchPendingTCPPairQEMU(context.Background(), rows, 11, 12)
			if err != nil || current == original {
				t.Fatal("new observation concealed continuity change", err)
			}
		})
	}
}
