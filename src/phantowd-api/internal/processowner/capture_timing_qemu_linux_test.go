//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The real capture/child boundary is used; only the private diagnostic opt-in
// normally set by the guarded QEMU constructor is enabled in this host test.
func TestCaptureFixtureTimingSeparatesOriginalChildAndParentWork(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/printf", []string{"%s", "unchanged"}, nil)
	c.fixtureTiming = &captureFixtureTiming{}
	result, err := c.Capture(context.Background())
	if err != nil || string(result.Stdout) != "unchanged" {
		t.Fatal("diagnostics changed capture result", err)
	}
	cost, err := c.NativeCaptureCostQEMU(context.Background())
	if err != nil || !cost.Present || !cost.InputChecked || !cost.Started || !cost.WaitReturned || !cost.ChildReaped {
		t.Fatal("original child timing incomplete", cost, err)
	}
	if cost.TotalNS <= 0 || cost.InputNS < 0 || cost.LaunchNS < 0 || cost.WaitNS < 0 || cost.PostNS < 0 ||
		cost.TotalNS != cost.InputNS+cost.LaunchNS+cost.WaitNS+cost.PostNS || cost.ChildUserNS < 0 || cost.ChildSystemNS < 0 {
		t.Fatal("overlapping, negative or fabricated elapsed accounting", cost)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	after, err := c.NativeCaptureCostQEMU(context.Background())
	if err != nil || after != cost {
		t.Fatal("close rewrote completed diagnostic evidence", after, err)
	}
}

func TestCaptureFixtureTimingDefaultAbsentAndRefusalsPreserveEvidence(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/printf", []string{"%s", "default"}, nil)
	if _, err := c.Capture(context.Background()); err != nil {
		t.Fatal(err)
	}
	if cost, err := c.NativeCaptureCostQEMU(context.Background()); err != nil || cost != (NativeCaptureCostQEMU{}) || c.fixtureTiming != nil {
		t.Fatal("generic capture acquired fixture diagnostics", cost, err)
	}
	traced, path := captureFixture(t, "/usr/bin/cat", nil, []byte("original"))
	traced.fixtureTiming = &captureFixtureTiming{}
	if cost, err := traced.NativeCaptureCostQEMU(context.Background()); err != nil || cost.Present {
		t.Fatal("unattempted capture has fabricated cost", cost, err)
	}
	if err := os.WriteFile(path, []byte("replaced"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := traced.Capture(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("diagnostics weakened drift refusal", err)
	}
	cost, err := traced.NativeCaptureCostQEMU(context.Background())
	if err != nil || !cost.Present || cost.InputChecked || cost.Started || cost.WaitReturned || cost.ChildReaped ||
		cost.TotalNS != cost.InputNS || cost.ChildUserNS != 0 || cost.ChildSystemNS != 0 {
		t.Fatal("refused input fabricated completed phases or child", cost, err)
	}
	if _, err := traced.Capture(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("refused capture retried", err)
	}
	copied := *traced
	if _, err := copied.NativeCaptureCostQEMU(context.Background()); !errors.Is(err, ErrInvalid) {
		t.Fatal("copied observer admitted", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := traced.NativeCaptureCostQEMU(ctx); !errors.Is(err, context.Canceled) {
		t.Fatal("canceled observation admitted", err)
	}
	after, err := traced.NativeCaptureCostQEMU(context.Background())
	if err != nil || after != cost {
		t.Fatal("refused calls rewrote original timing", after, err)
	}
}

func TestCaptureFixtureTimingCancellationKeepsOriginalStopContract(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/sleep", []string{"60"}, nil)
	c.fixtureTiming = &captureFixtureTiming{}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if result, err := c.Capture(ctx); !errors.Is(err, context.DeadlineExceeded) || !zeroCapture(result) {
		t.Fatal("diagnostics published canceled result", result, err)
	}
	cost, err := c.NativeCaptureCostQEMU(context.Background())
	if err != nil || !cost.Present || !cost.InputChecked || !cost.Started || !cost.WaitReturned ||
		cost.TotalNS != cost.InputNS+cost.LaunchNS+cost.WaitNS+cost.PostNS {
		t.Fatal("canceled capture phases lost", cost, err)
	}
	if settled, err := c.Settled(context.Background()); !settled || err != nil {
		t.Fatal("original stop contract changed", settled, err)
	}
	if _, err := c.Capture(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("canceled lifetime restarted", err)
	}
}

func TestCaptureFixtureTimingKernelWaitAccountingIncludesWaitedDescendant(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/python3", []string{"-I", "-S", "-c", `import os,time
pid=os.fork()
if pid==0:
    start=time.process_time()
    while time.process_time()-start < 0.08: pass
    os._exit(0)
_,_,usage=os.wait4(pid,0)
os.write(1,str(int(usage.ru_utime*1000000000)).encode())
`}, nil)
	c.fixtureTiming = &captureFixtureTiming{}
	result, err := c.Capture(context.Background())
	if err != nil || result.Kind != CaptureExited || result.ExitCode != 0 {
		t.Fatal("fixed waited-descendant fixture failed", result, err)
	}
	descendantUserNS, err := strconv.ParseInt(strings.TrimSpace(string(result.Stdout)), 10, 64)
	if err != nil || descendantUserNS < int64(10*time.Millisecond) {
		t.Fatal("fixture did not observe descendant CPU", descendantUserNS, err)
	}
	cost, err := c.NativeCaptureCostQEMU(context.Background())
	// Timeval conversion/rounding may differ by a microsecond. This compares
	// nested kernel wait accounting, NOT CPU to a wall-clock timing threshold.
	if err != nil || !cost.ChildReaped || cost.ChildUserNS+int64(time.Microsecond) < descendantUserNS {
		t.Fatal("wait record incorrectly excludes waited-descendant CPU", cost, descendantUserNS, err)
	}
}
