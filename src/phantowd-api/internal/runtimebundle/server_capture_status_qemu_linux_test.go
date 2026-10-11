//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

func captureStatusFixtureQEMU() string {
	s := pendingStatusFixtureQEMU()
	for _, pair := range [][2]string{{"qpsecond", "nobody"}, {"2001", "65534"}, {"writable", "readonly"}, {"pending-write", "capture-read"}, {"0x0012019f", "0x00120089"}, {`"WRITE_DATA":true`, `"WRITE_DATA":false`}} {
		s = strings.ReplaceAll(s, pair[0], pair[1])
	}
	return s
}

func TestServerCaptureStatusResultRequiresExactIsolatedHelperReceipt(t *testing.T) {
	good := processowner.CaptureResult{Kind: processowner.CaptureExited, ExitCode: 0, Stdout: []byte(captureStatusFixtureQEMU()), Stderr: []byte(nativeCredentialHandoff + "WARNING: no network interfaces found\n")}
	if _, err := parseServerCaptureStatusResultQEMU(good, nil); err != nil {
		t.Fatal("actual isolated STATUS helper receipt refused", err)
	}
	for _, stderr := range []string{"", nativeCredentialHandoff, nativeCredentialHandoff + "WARNING: no network interfaces found", "WARNING: no network interfaces found\n" + nativeCredentialHandoff, string(good.Stderr) + "unexpected\n", string(good.Stderr) + "WARNING: no network interfaces found\n"} {
		bad := good
		bad.Stderr = []byte(stderr)
		if value, err := parseServerCaptureStatusResultQEMU(bad, nil); err == nil || value != (pendingStatusQEMU{}) {
			t.Fatal("missing/foreign/reordered receipt admitted")
		}
	}
	if _, err := parseServerCaptureStatusResultQEMU(good, errors.New("uncertain execution")); err == nil {
		t.Fatal("uncertain execution admitted")
	}
	bad := good
	bad.ExitCode = 1
	if _, err := parseServerCaptureStatusResultQEMU(bad, nil); err == nil {
		t.Fatal("failed helper admitted")
	}
	bad = good
	bad.Kind = processowner.CaptureSignaled
	if _, err := parseServerCaptureStatusResultQEMU(bad, nil); err == nil {
		t.Fatal("signaled helper admitted")
	}
}

func TestServerCaptureStatusRequiresFixedReadOnlyProfile(t *testing.T) {
	good := captureStatusFixtureQEMU()
	observed, err := parseServerCaptureStatusQEMU([]byte(good))
	if err != nil || observed.session != "1000000000002" || observed.tree != "21" || observed.device != 8 || observed.inode != 123456 || observed.shareFileID != 42 {
		t.Fatal("fixed capture STATUS refused", err)
	}
	if _, err := parsePendingStatusQEMU([]byte(good)); err == nil {
		t.Fatal("capture profile widened the original parser")
	}
	if _, err := parseServerCaptureStatusQEMU([]byte(pendingStatusFixtureQEMU())); err == nil {
		t.Fatal("native writable profile substituted for capture")
	}
}

func TestServerCaptureStatusRefusesForeignIncompleteOrWritableObservation(t *testing.T) {
	good := captureStatusFixtureQEMU()
	for _, pair := range [][2]string{
		{`"username":"nobody"`, `"username":"Nobody"`}, {`"uid":65534`, `"uid":0`}, {`"gid":65534`, `"gid":null`},
		{`"service":"readonly"`, `"service":"Readonly"`}, {`"service_path":"/shares/readonly"`, `"service_path":"/shares/writable"`},
		{`"filename":"capture-read"`, `"filename":"other"`}, {`"hex":"0x00120089"`, `"hex":"0x0012019f"`},
		{`"READ_DATA":true`, `"READ_DATA":false`}, {`"WRITE_DATA":false`, `"WRITE_DATA":true`}, {`"WRITE_DATA":false`, `"WRITE_DATA":null`},
		{`"devid":8`, `"devid":null`}, {`"extid":0`, `"extid":1`}, {`"num_pending_deletes":0`, `"num_pending_deletes":1`},
		{`"opens":{`, `"opens":{"other":{},`}, {`"sessions":{`, `"sessions":{"other":{},`},
		{`"version":"4.22.11"`, `"version":"4.22.11","unknown":1,"unknown":2`},
	} {
		if value, err := parseServerCaptureStatusQEMU([]byte(strings.Replace(good, pair[0], pair[1], 1))); err == nil || value != (pendingStatusQEMU{}) {
			t.Fatal("foreign/incomplete/writable capture observation admitted", pair)
		}
	}
	for _, bad := range []string{"", "null", good + "{}", strings.Repeat(" ", 1<<20) + good} {
		if value, err := parseServerCaptureStatusQEMU([]byte(bad)); err == nil || value != (pendingStatusQEMU{}) {
			t.Fatal("incomplete/unbounded capture JSON admitted")
		}
	}
}

func TestServerCaptureWorkerRefusesAbsentCanceledBusyAndUnsettledHelper(t *testing.T) {
	file, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	var absent *serverObserverRuntimeQEMU
	if absent.observeCaptureWorkerQEMU(context.Background(), file, unix.Stat_t{}) == nil {
		t.Fatal("absent runtime admitted")
	}
	r := &serverObserverRuntimeQEMU{gate: make(chan struct{}, 1)}
	r.self = r
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if !errors.Is(r.observeCaptureWorkerQEMU(canceled, file, unix.Stat_t{}), context.Canceled) || r.review {
		t.Fatal("canceled observation had effects")
	}
	r.gate <- struct{}{}
	if !errors.Is(r.observeCaptureWorkerQEMU(context.Background(), file, unix.Stat_t{}), processowner.ErrBusy) {
		t.Fatal("exclusive gate bypassed")
	}
	<-r.gate
	if r.observeCaptureWorkerQEMU(context.Background(), file, unix.Stat_t{}) == nil || r.captureWorker != nil {
		t.Fatal("unstarted runtime admitted worker")
	}
	// Invalid concrete capture is not a mock of successful settlement. A failed
	// settlement must retain the actual opened original, not close past it.
	r.captureStatus = &processowner.CaptureOwner{}
	r.captureWorker = &serverCaptureWorkerQEMU{proc: file}
	if r.Close() == nil || !r.review || r.closed {
		t.Fatal("uncertain helper settlement admitted release")
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("uncertain helper discarded worker original", err)
	}
}
