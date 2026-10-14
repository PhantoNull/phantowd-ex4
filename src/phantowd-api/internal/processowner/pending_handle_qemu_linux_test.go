//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestPendingHandleNoticesExactPrefixesNeverPublishPartial(t *testing.T) {
	h := PendingHandleObservationQEMU{SessionID: 4294967297, TreeID: 3, PersistentID: 4294967301, VolatileID: 4294967303}
	for _, closing := range []bool{false, true} {
		expected := h.notice() + pendingOpenNoticeQEMU
		if closing {
			expected += h.notice() + pendingCloseNoticeQEMU
		}
		for count := 0; count <= len(expected); count++ {
			observed, ready, err := pendingHandleNoticesQEMU([]byte(expected[:count]), nil, closing, h)
			if err != nil || ready != (count == len(expected)) || (ready && observed != h) || (!ready && observed != (PendingHandleObservationQEMU{})) {
				t.Fatal(closing, count, observed, ready, err)
			}
		}
	}
}

func TestPendingHandleNoticesInvalidFieldsOrderDriftAndOutputRefuse(t *testing.T) {
	h := PendingHandleObservationQEMU{SessionID: 4294967297, TreeID: 3, PersistentID: 4294967301, VolatileID: 4294967303}
	base := h.notice() + pendingOpenNoticeQEMU
	bad := []string{pendingOpenNoticeQEMU, h.notice() + pendingCloseNoticeQEMU,
		base + "x", base + base, "unknown\n", strings.Repeat("x", 257),
		strings.Replace(base, "proof=false", "proof=true", 1),
		strings.Replace(base, "scope=qemu-only", "scope=product", 1),
		strings.Replace(base, "session=", "session=+", 1),
		strings.Replace(base, "session=", "session=0", 1),
		strings.Replace(base, "tree=3", "tree=4294967296", 1),
		strings.Replace(base, " ", "\t", 1), strings.Replace(base, "\n", "\r\n", 1)}
	for _, name := range []string{"session=4294967297", "tree=3", "persistent=4294967301", "volatile=4294967303"} {
		for _, value := range []string{"0", "18446744073709551615", "18446744073709551616", "-1", "1x", ""} {
			bad = append(bad, strings.Replace(base, name, strings.Split(name, "=")[0]+"="+value, 1))
		}
	}
	for _, output := range bad {
		if observed, ready, err := pendingHandleNoticesQEMU([]byte(output), nil, false, h); observed != (PendingHandleObservationQEMU{}) || ready || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("malformed observation published", observed, ready, err)
		}
	}
	for _, changed := range []PendingHandleObservationQEMU{
		{SessionID: 9, TreeID: h.TreeID, PersistentID: h.PersistentID, VolatileID: h.VolatileID},
		{SessionID: h.SessionID, TreeID: 9, PersistentID: h.PersistentID, VolatileID: h.VolatileID},
		{SessionID: h.SessionID, TreeID: h.TreeID, PersistentID: 9, VolatileID: h.VolatileID},
		{SessionID: h.SessionID, TreeID: h.TreeID, PersistentID: h.PersistentID, VolatileID: 9},
	} {
		if observed, ready, err := pendingHandleNoticesQEMU([]byte(base+changed.notice()+pendingCloseNoticeQEMU), nil, true, h); observed != (PendingHandleObservationQEMU{}) || ready || err == nil {
			t.Fatal("drift accepted")
		}
	}
	for _, closing := range []bool{false, true} {
		if observed, ready, err := pendingHandleNoticesQEMU([]byte(base), []byte("error"), closing, h); observed != (PendingHandleObservationQEMU{}) || ready || err == nil {
			t.Fatal("stderr accepted")
		}
	}
	if observed, ready, err := pendingHandleNoticesQEMU([]byte(base+h.notice()+pendingCloseNoticeQEMU), nil, true, PendingHandleObservationQEMU{}); observed != (PendingHandleObservationQEMU{}) || ready || err == nil {
		t.Fatal("missing original accepted")
	}
}

func TestPendingHandleAdapterLatchesOnlyCompleteInitialAndNeverRebinds(t *testing.T) {
	h := PendingHandleObservationQEMU{SessionID: 11, TreeID: 3, PersistentID: 17, VolatileID: 19}
	c := &PendingClientQEMU{handleMode: true, stdout: newDiagnosticRing(), stderr: newDiagnosticRing()}
	_, _ = c.stdout.Write([]byte(h.notice()))
	if ready, err := c.notices(false); ready || err != nil || c.handleInitial.valid() {
		t.Fatal("partial startup cached")
	}
	_, _ = c.stdout.Write([]byte(pendingOpenNoticeQEMU))
	if ready, err := c.notices(false); !ready || err != nil || c.handleInitial != h {
		t.Fatal("initial not cached")
	}
	changed := h
	changed.VolatileID++
	c.stdout = newDiagnosticRing()
	_, _ = c.stdout.Write([]byte(changed.notice() + pendingOpenNoticeQEMU))
	if ready, err := c.notices(false); ready || err == nil || c.handleInitial != h {
		t.Fatal("initial replaced")
	}
	c.stderr = newDiagnosticRing()
	_, _ = c.stderr.Write([]byte("error"))
	if ready, err := c.notices(false); ready || err == nil || c.handleInitial != h {
		t.Fatal("stderr ignored")
	}
}

func TestPendingInitialHandleGuardNeverReturnsUnownedMetadata(t *testing.T) {
	if client, err := NewPendingHandleClientQEMU(nil, nil, nil, []byte("fixture")); client != nil || err == nil {
		t.Fatal("host/missing authority accepted")
	}
	var absent *PendingClientQEMU
	if h, err := absent.InitialHandleObservationQEMU(context.Background()); h != (PendingHandleObservationQEMU{}) || err == nil {
		t.Fatal("nil accepted")
	}
	c := &PendingClientQEMU{gate: make(chan struct{}, 1), handleMode: true, handleInitial: PendingHandleObservationQEMU{SessionID: 1, TreeID: 2, PersistentID: 3, VolatileID: 4}, started: true}
	c.self = c
	if h, err := c.InitialHandleObservationQEMU(context.Background()); h != (PendingHandleObservationQEMU{}) || err == nil {
		t.Fatal("missing original process accepted")
	}
	copy := *c
	if _, err := copy.InitialHandleObservationQEMU(context.Background()); err == nil {
		t.Fatal("copy accepted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.InitialHandleObservationQEMU(canceled); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}
