//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"errors"
	"os"
	"reflect"
	"testing"
)

func TestPendingClientNoticePrefixesAndExactCloseOnlyOrder(t *testing.T) {
	for _, closing := range []bool{false, true} {
		expected := pendingOpenNoticeQEMU
		if closing {
			expected += pendingCloseNoticeQEMU
		}
		for count := 0; count <= len(expected); count++ {
			ready, err := pendingNoticesQEMU([]byte(expected[:count]), nil, closing)
			if err != nil || ready != (count == len(expected)) {
				t.Fatal(count, ready, err)
			}
		}
		for _, bad := range []string{expected + "x", expected + expected, pendingCloseNoticeQEMU,
			"PHANTOWD_SMB_WRITE_CLIENT_REFUSED scope=qemu-only\n", "garbage",
			pendingOpenNoticeQEMU + "PHANTOWD_SMB_WRITE_CLIENT_CALL_NOTICE scope=qemu-only proof=false\n"} {
			if ready, err := pendingNoticesQEMU([]byte(bad), nil, closing); ready || !errors.Is(err, ErrReviewRequired) {
				t.Fatal("unexpected telemetry accepted")
			}
		}
		if ready, err := pendingNoticesQEMU([]byte(expected), []byte("failure"), closing); ready || err == nil {
			t.Fatal("stderr ignored")
		}
	}
}

func TestPendingClientSecretBoundaries(t *testing.T) {
	for _, value := range [][]byte{nil, {}, []byte("space inside"), []byte("newline\n"), {0}, {127}, bytes.Repeat([]byte{'x'}, 129)} {
		if validPendingSecretQEMU(value) {
			t.Fatal("invalid secret accepted")
		}
	}
	for _, value := range [][]byte{[]byte("x"), bytes.Repeat([]byte{'~'}, 128)} {
		if !validPendingSecretQEMU(value) {
			t.Fatal("bounded printable secret refused")
		}
	}
}

func TestPendingClientCommandHasFixedDistinctOutputAndDescriptorRoles(t *testing.T) {
	// Description only; no command/helper is executed by this host test.
	var files []*os.File
	for index := 0; index < 5; index++ {
		file, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		files = append(files, file)
	}
	pins, control, secret := files[:3], files[3], files[4]
	out, diagnostic := newDiagnosticRing(), newDiagnosticRing()
	command := pendingCommandQEMU(pins, control, secret, out, diagnostic)
	if command.Path != "/proc/self/fd/6" || command.Dir != "/" || !reflect.DeepEqual(command.Env, []string{"LC_ALL=C"}) ||
		!reflect.DeepEqual(command.Args, []string{"phantowd-pending-write-launcher"}) || command.Stdin != control ||
		command.Stdout == command.Stderr || !reflect.DeepEqual(command.ExtraFiles, []*os.File{secret, pins[1], pins[2], pins[0]}) ||
		!command.SysProcAttr.Setpgid || command.SysProcAttr.Credential == nil || command.SysProcAttr.Credential.Uid != 0 ||
		command.SysProcAttr.Credential.Gid != 0 || len(command.SysProcAttr.Credential.Groups) != 0 {
		t.Fatal("handoff ABI drift")
	}
}

func TestPendingClientHostGuardNilCopyCancellationBusyAndReviewRefuse(t *testing.T) {
	if value, err := NewPendingClientQEMU(nil, nil, nil, []byte("test-only")); value != nil || err == nil {
		t.Fatal("host/missing authority admitted")
	}
	var absent *PendingClientQEMU
	if absent.Start(context.Background()) == nil || absent.CloseClient(context.Background()) == nil || absent.Stop(context.Background()) == nil || absent.Close() == nil {
		t.Fatal("nil admitted")
	}
	c := &PendingClientQEMU{gate: make(chan struct{}, 1)}
	c.self = c
	copied := *c
	if copied.Start(context.Background()) == nil || copied.Close() == nil {
		t.Fatal("copied owner admitted")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(c.Start(cancelled), context.Canceled) || c.started {
		t.Fatal("cancelled operation had effects")
	}
	c.gate <- struct{}{}
	if !errors.Is(c.Start(context.Background()), ErrBusy) || !errors.Is(c.Close(), ErrBusy) {
		t.Fatal("concurrent operation admitted")
	}
	<-c.gate
	c.review = true
	if c.Start(context.Background()) == nil || c.CloseClient(context.Background()) == nil || c.Close() == nil || !c.review {
		t.Fatal("review released or restarted")
	}
}

func TestPendingClientNeverLaunchedReleaseClearsSecretAndStickyFailureRetainsLaterPins(t *testing.T) {
	// Terminal bookkeeping with real file descriptors, NOT admitted roots or
	// a fabricated healthy process. No constructor/launch/SMB is exercised here.
	for _, uncertain := range []bool{false, true} {
		first, err := os.Open(os.DevNull)
		if err != nil {
			t.Fatal(err)
		}
		later, err := os.Open(os.DevNull)
		if err != nil {
			_ = first.Close()
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = later.Close() })
		secret := []byte("test-only-noncredential")
		c := &PendingClientQEMU{gate: make(chan struct{}, 1), pins: []*os.File{first, later}, secret: secret}
		c.self = c
		if uncertain {
			if first.Close() != nil {
				t.Fatal("fixture close failed")
			}
			if !errors.Is(c.Close(), ErrReviewRequired) || c.releaseErr == nil || len(c.pins) != 2 {
				t.Fatal("uncertain close released later originals")
			}
			witness := c.releaseErr
			if c.Close() == nil || c.releaseErr != witness || len(c.pins) != 2 {
				t.Fatal("uncertain close retried")
			}
			if _, err := later.Stat(); err != nil {
				t.Fatal("later reference lost")
			}
		} else {
			if c.Close() != nil || c.Close() != nil || len(c.pins) != 0 {
				t.Fatal("never-launched release failed")
			}
			if _, err := first.Stat(); err == nil {
				t.Fatal("first reference leaked")
			}
			if _, err := later.Stat(); err == nil {
				t.Fatal("later reference leaked")
			}
		}
		if c.secret != nil || !bytes.Equal(secret, make([]byte, len(secret))) {
			t.Fatal("secret retained after release")
		}
	}
}

func TestPendingClientRootRefusesOrdinaryDirectoryAndClosedDescriptor(t *testing.T) {
	root, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if pin, err := duplicatePendingRootQEMU(root); pin != nil || err == nil {
		t.Fatal("ordinary writable root admitted")
	}
	if root.Close() != nil {
		t.Fatal("fixture close failed")
	}
	if pin, err := duplicatePendingRootQEMU(root); pin != nil || err == nil {
		t.Fatal("closed root admitted")
	}
}
