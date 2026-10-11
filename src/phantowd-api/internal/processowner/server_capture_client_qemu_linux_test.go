//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
)

func TestServerCaptureClientNoticesRequireCompleteSameOpenSequence(t *testing.T) {
	h := PendingHandleObservationQEMU{SessionID: 4294967297, TreeID: 3, PersistentID: 4294967301, VolatileID: 4294967303}
	initial := fmt.Sprintf("PHANTOWD_CAPTURE_CLIENT_HANDLE session=%d tree=%d persistent=%d volatile=%d scope=qemu-only proof=false\n", h.SessionID, h.TreeID, h.PersistentID, h.VolatileID)
	initial += "PHANTOWD_CAPTURE_CLIENT_OPEN scope=qemu-only proof=false\n"
	for samples := uint8(0); samples <= 2; samples++ {
		for _, closing := range []bool{false, true} {
			expected := initial
			for sample := uint8(1); sample <= samples; sample++ {
				expected += fmt.Sprintf("PHANTOWD_CAPTURE_CLIENT_READ sequence=%d scope=qemu-only proof=false\n", sample)
			}
			if closing {
				expected += "PHANTOWD_CAPTURE_CLIENT_CLOSE scope=qemu-only proof=false\n"
			}
			for count := 0; count <= len(expected); count++ {
				observed, ready, err := serverCaptureClientNoticesQEMU([]byte(expected[:count]), nil, samples, closing, h)
				if err != nil || ready != (count == len(expected)) || (ready && observed != h) || (!ready && observed != (PendingHandleObservationQEMU{})) {
					t.Fatalf("samples=%d closing=%t prefix=%d ready=%t err=%v", samples, closing, count, ready, err)
				}
			}
		}
	}
	for count := 0; count <= len(initial); count++ {
		observed, ready, err := serverCaptureClientNoticesQEMU([]byte(initial[:count]), nil, 0, false, PendingHandleObservationQEMU{})
		if err != nil || ready != (count == len(initial)) || (ready && observed != h) || (!ready && observed != (PendingHandleObservationQEMU{})) {
			t.Fatal("incomplete initial tuple was published", count, ready, err)
		}
	}
}

func TestServerCaptureClientNoticesRefuseDriftUnrequestedReadsAndOtherProtocols(t *testing.T) {
	h := PendingHandleObservationQEMU{SessionID: 11, TreeID: 3, PersistentID: 17, VolatileID: 19}
	base := serverCaptureClientHandleNoticeQEMU(h) + serverCaptureClientOpenNoticeQEMU
	read1 := "PHANTOWD_CAPTURE_CLIENT_READ sequence=1 scope=qemu-only proof=false\n"
	read2 := "PHANTOWD_CAPTURE_CLIENT_READ sequence=2 scope=qemu-only proof=false\n"
	for _, bad := range []string{
		"garbage", base + "x", base + base, serverCaptureClientOpenNoticeQEMU,
		pendingOpenNoticeQEMU, h.notice() + pendingOpenNoticeQEMU,
		base + read1, base + read2, base + read1 + read2,
		base + serverCaptureClientCloseNoticeQEMU,
		strings.Replace(base, "session=11", "session=12", 1),
		strings.Replace(base, "tree=3", "tree=4", 1),
		strings.Replace(base, "persistent=17", "persistent=18", 1),
		strings.Replace(base, "volatile=19", "volatile=20", 1),
		strings.Replace(base, "proof=false", "proof=true", 1),
		strings.Replace(base, "scope=qemu-only", "scope=product", 1),
		strings.Replace(base, "\n", "\r\n", 1),
	} {
		observed, ready, err := serverCaptureClientNoticesQEMU([]byte(bad), nil, 0, false, h)
		if observed != (PendingHandleObservationQEMU{}) || ready || !errors.Is(err, ErrReviewRequired) {
			t.Fatal("drift or unrequested output admitted")
		}
	}
	for _, bad := range []string{base + read2, base + read1 + read1, base + read1 + read2 + read1, base + read1 + serverCaptureClientCloseNoticeQEMU} {
		if _, ready, err := serverCaptureClientNoticesQEMU([]byte(bad), nil, 2, false, h); ready || err == nil {
			t.Fatal("out-of-order/duplicate/read-close admitted")
		}
	}
	for _, replacement := range []string{"0", "18446744073709551615", "18446744073709551616", "-1", "+11", "011", "", "1x"} {
		if _, ready, err := serverCaptureClientNoticesQEMU([]byte(strings.Replace(base, "session=11", "session="+replacement, 1)), nil, 0, false, PendingHandleObservationQEMU{}); ready || err == nil {
			t.Fatal("noncanonical initial field accepted", replacement)
		}
	}
	for _, replacement := range []string{"0", "4294967295", "4294967296", "03"} {
		if _, ready, err := serverCaptureClientNoticesQEMU([]byte(strings.Replace(base, "tree=3", "tree="+replacement, 1)), nil, 0, false, PendingHandleObservationQEMU{}); ready || err == nil {
			t.Fatal("invalid tree accepted")
		}
	}
	for _, invalid := range []struct {
		out, diagnostic []byte
		samples         uint8
		closing         bool
		initial         PendingHandleObservationQEMU
	}{
		{[]byte(base), []byte("error"), 0, false, h},
		{bytes.Repeat([]byte{'x'}, 4097), nil, 0, false, h},
		{append([]byte(serverCaptureClientHandlePrefixQEMU), bytes.Repeat([]byte{'x'}, 257)...), nil, 0, false, PendingHandleObservationQEMU{}},
		{[]byte(base), nil, 3, false, h},
		{[]byte(base), nil, 1, false, PendingHandleObservationQEMU{}},
		{[]byte(base), nil, 0, true, PendingHandleObservationQEMU{}},
		{[]byte(base), nil, 0, false, PendingHandleObservationQEMU{SessionID: 1}},
	} {
		if observed, ready, err := serverCaptureClientNoticesQEMU(invalid.out, invalid.diagnostic, invalid.samples, invalid.closing, invalid.initial); observed != (PendingHandleObservationQEMU{}) || ready || err == nil {
			t.Fatal("invalid capture state accepted")
		}
	}
}

func TestServerCaptureClientDedicatedLifecycleRefusesHostNilCopyCancelBusyAndReview(t *testing.T) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 16 {
		client, err := NewServerCaptureClientQEMU(nil, nil, nil, []byte("test-only"))
		if client != nil || err == nil {
			t.Fatal("host/missing inputs admitted")
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("constructor refusal leaked descriptors", err)
	}
	var absent *ServerCaptureClientQEMU
	if absent.Start(context.Background()) == nil || absent.ReadSample(context.Background()) == nil || absent.CloseClient(context.Background()) == nil || absent.Stop(context.Background()) == nil || absent.Close() == nil {
		t.Fatal("nil adapter admitted")
	}
	// Only lifecycle refusal bookkeeping; no fabricated healthy process or SMB.
	inner := &PendingClientQEMU{gate: make(chan struct{}, 1), captureMode: true, handleMode: true}
	inner.self = inner
	client := &ServerCaptureClientQEMU{adapter: inner}
	client.self = client
	copied := *client
	if copied.Start(context.Background()) == nil || copied.ReadSample(context.Background()) == nil || copied.Close() == nil {
		t.Fatal("copied adapter admitted")
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(client.ReadSample(canceled), context.Canceled) || inner.captureReads != 0 || inner.review {
		t.Fatal("canceled read had effects")
	}
	inner.gate <- struct{}{}
	if !errors.Is(client.ReadSample(context.Background()), ErrBusy) || !errors.Is(client.Close(), ErrBusy) {
		t.Fatal("concurrent operation admitted")
	}
	<-inner.gate
	if client.ReadSample(context.Background()) == nil || inner.captureReads != 0 {
		t.Fatal("unstarted read admitted")
	}
	inner.review = true
	if client.Start(context.Background()) == nil || client.ReadSample(context.Background()) == nil || client.CloseClient(context.Background()) == nil || client.Close() == nil || !inner.review {
		t.Fatal("review retried/released")
	}
}

func TestServerCaptureClientAccumulatedNoticesNeverLatchPartialOrAcceptUnrequestedRead(t *testing.T) {
	h := PendingHandleObservationQEMU{SessionID: 11, TreeID: 3, PersistentID: 17, VolatileID: 19}
	c := &PendingClientQEMU{captureMode: true, handleMode: true, stdout: newDiagnosticRing(), stderr: newDiagnosticRing()}
	header := serverCaptureClientHandleNoticeQEMU(h)
	_, _ = c.stdout.Write([]byte(header))
	if ready, err := c.notices(false); ready || err != nil || c.handleInitial.valid() {
		t.Fatal("partial OPEN latched")
	}
	_, _ = c.stdout.Write([]byte(serverCaptureClientOpenNoticeQEMU))
	if ready, err := c.notices(false); !ready || err != nil || c.handleInitial != h {
		t.Fatal("complete OPEN not latched")
	}
	_, _ = c.stdout.Write([]byte("PHANTOWD_CAPTURE_CLIENT_READ sequence=1 scope=qemu-only proof=false\n"))
	if ready, err := c.notices(false); ready || !errors.Is(err, ErrReviewRequired) || c.handleInitial != h {
		t.Fatal("unrequested READ accepted")
	}
	// Fixed requested-count bookkeeping, not actual command/process/SMB proof.
	c.captureReads = 1
	if ready, err := c.notices(false); !ready || err != nil || c.handleInitial != h {
		t.Fatal("requested READ not accepted")
	}
	_, _ = c.stdout.Write([]byte(serverCaptureClientCloseNoticeQEMU))
	if ready, err := c.notices(true); !ready || err != nil || c.handleInitial != h {
		t.Fatal("same-open CLOSE not accepted")
	}
	if ready, err := c.notices(false); ready || err == nil {
		t.Fatal("closed stream accepted as live")
	}
	if ready, err := pendingNoticesQEMU(c.stdout.snapshot(), nil, true); ready || err == nil {
		t.Fatal("old protocol accepted new capture notices")
	}
}
