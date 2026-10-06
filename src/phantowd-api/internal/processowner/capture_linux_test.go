//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

func captureFixture(t *testing.T, executable string, args []string, data []byte) (*CaptureOwner, string) {
	t.Helper()
	path := t.TempDir() + "/input"
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	code, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer code.Close()
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	c, err := NewCapture(CaptureSpec{ExecutableLabel: "/fixed/capture", Args: args,
		Timeout: 3 * time.Second, StopTimeout: 30 * time.Millisecond}, code, input)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = c.Close(context.Background()) })
	return c, path
}

func zeroCapture(r CaptureResult) bool {
	return r.Kind == CaptureUnknown && r.ExitCode == 0 && r.Stdout == nil && r.Stderr == nil
}

func TestCaptureRetainsFixedFilesAndCopiesArguments(t *testing.T) {
	args := []string{"%s", "original"}
	c, _ := captureFixture(t, "/usr/bin/printf", args, nil)
	args[1] = "changed"
	result, err := c.Capture(context.Background())
	if err != nil || result.Kind != CaptureExited || result.ExitCode != 0 || string(result.Stdout) != "original" || len(result.Stderr) != 0 {
		t.Fatal("fixed input/ordinary exit lost", err)
	}
	if c.current != nil {
		t.Fatal("normal exit retained child ownership")
	}
	result, err = c.Capture(context.Background())
	if !zeroCapture(result) || !errors.Is(err, ErrCaptureConsumed) {
		t.Fatal("capture repeated", err)
	}
	if ok, err := c.Settled(context.Background()); !ok || err != nil {
		t.Fatal("not settled", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if c.executable != nil || c.input != nil {
		t.Fatal("verified close kept pins")
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal("close not idempotent", err)
	}
	result, err = c.Capture(context.Background())
	if !zeroCapture(result) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed capture reopened", err)
	}
}

func TestCaptureCompleteRegularStdinAtBound(t *testing.T) {
	data := bytes.Repeat([]byte{'x'}, MaxCaptureInput)
	c, _ := captureFixture(t, "/usr/bin/cat", nil, data)
	result, err := c.Capture(context.Background())
	if err != nil || result.Kind != CaptureExited || !bytes.Equal(result.Stdout, data) {
		t.Fatal("regular stdin/bound failed", err)
	}
}

func TestCaptureOrdinaryNonzeroIsNotSignalOrSuccessfulCollection(t *testing.T) {
	for _, exit := range []string{"8", "143", "255"} {
		c, _ := captureFixture(t, "/usr/bin/python3", []string{"-I", "-S", "-c",
			"import os,sys; os.write(1,b'out'); os.write(2,b'err'); sys.exit(int(sys.argv[1]))", exit}, nil)
		result, err := c.Capture(context.Background())
		if err != nil || result.Kind != CaptureExited || string(result.Stdout) != "out" || string(result.Stderr) != "err" {
			t.Fatal("ordinary exit or independent streams lost", err)
		}
		if (exit == "143" && result.ExitCode != 143) || (exit == "255" && result.ExitCode != 255) || (exit == "8" && result.ExitCode != 8) {
			t.Fatal("not genuine 8-bit exit")
		}
	}
}

func TestCaptureSignalNeverBecomesSMARTExitBits(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/python3", []string{"-I", "-S", "-c",
		"import os,signal; os.write(1,b'untrusted report'); os.kill(os.getpid(),signal.SIGTERM)"}, nil)
	result, err := c.Capture(context.Background())
	if err != nil || result.Kind != CaptureSignaled || result.ExitCode != -1 || result.Stdout != nil || result.Stderr != nil {
		t.Fatal("signal exposed an ordinary exit or report", err)
	}
}

func TestCaptureStreamOverflowDiscardsWholeResult(t *testing.T) {
	for _, stream := range []string{"stdout", "stderr"} {
		script := "import os; os.write(1,b'x'*65537)"
		if stream == "stderr" {
			script = "import os; os.write(2,b'x'*4097)"
		}
		c, _ := captureFixture(t, "/usr/bin/python3", []string{"-I", "-S", "-c", script}, nil)
		result, err := c.Capture(context.Background())
		if !zeroCapture(result) || !errors.Is(err, ErrCaptureOutput) {
			t.Fatal("overflow returned partial evidence", err)
		}
	}
	bounded := newCaptureBuffer(4)
	if _, err := io.Copy(bounded, strings.NewReader("12345")); !errors.Is(err, ErrCaptureOutput) || len(bounded.data) != 0 || !bounded.overflow {
		t.Fatal("io.Copy bypassed bound", err)
	}
}

func TestCaptureDriftBeforeLaunchQuarantinesWithoutRetry(t *testing.T) {
	c, path := captureFixture(t, "/usr/bin/cat", nil, []byte("before"))
	if err := os.WriteFile(path, []byte("after!"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err := c.Capture(context.Background())
	if !zeroCapture(result) || !errors.Is(err, ErrReviewRequired) || c.current != nil || c.consumed {
		t.Fatal("drift started process", err)
	}
	if err := os.WriteFile(path, []byte("before"), 0600); err != nil {
		t.Fatal(err)
	}
	result, err = c.Capture(context.Background())
	if !zeroCapture(result) || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("restoration retried", err)
	}
}

func TestCaptureCanceledForcedCleanupAndBusyCalls(t *testing.T) {
	marker := t.TempDir() + "/ready"
	c, _ := captureFixture(t, "/usr/bin/python3", []string{"-I", "-S", "-c",
		"import signal,sys,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); open(sys.argv[1],'x').close(); time.sleep(60)", marker}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		result, err := c.Capture(ctx)
		if !zeroCapture(result) {
			done <- errors.New("cancellation returned report")
			return
		}
		done <- err
	}()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("fixture did not become ready")
		}
		time.Sleep(5 * time.Millisecond)
	}
	result, err := c.Capture(context.Background())
	if !zeroCapture(result) || !errors.Is(err, ErrBusy) {
		t.Fatal("active capture queued", err)
	}
	if err := c.Close(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal("close raced active capture", err)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatal("canceled capture result", err)
	}
	if !c.review || c.current == nil || c.executable == nil {
		t.Fatal("forced cleanup released ownership/pins")
	}
	result, err = c.Capture(context.Background())
	if !zeroCapture(result) || !errors.Is(err, ErrReviewRequired) {
		t.Fatal("review retried", err)
	}
	if ok, err := c.Settled(context.Background()); !ok || err != nil || !c.review || c.current != nil {
		t.Fatal("explicit absence verification cleared review", err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal("verified close failed", err)
	}
}

func TestCaptureInvalidAndCopiedHandlesNeverInvoke(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/cat", nil, nil)
	copied := *c
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, owner := range []*CaptureOwner{nil, {}, &copied} {
		result, err := owner.Capture(context.Background())
		if !zeroCapture(result) || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid owner accepted", err)
		}
	}
	result, err := c.Capture(ctx)
	if !zeroCapture(result) || !errors.Is(err, context.Canceled) || c.consumed {
		t.Fatal("precanceled capture consumed input", err)
	}
	if err := c.Close(ctx); !errors.Is(err, context.Canceled) || c.closed {
		t.Fatal("precanceled close released pins", err)
	}
	for _, value := range []any{c, c.spec, CaptureResult{}} {
		if data, err := json.Marshal(value); data != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("private capture serialized")
		}
	}
}

func TestCaptureConstructorRefusesUnsafeInputAndLeaksNoPins(t *testing.T) {
	code, err := os.Open("/usr/bin/cat")
	if err != nil {
		t.Fatal(err)
	}
	defer code.Close()
	path := t.TempDir() + "/input"
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	rw, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	directory, err := os.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer directory.Close()
	pipe, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer pipe.Close()
	defer writer.Close()
	char, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer char.Close()
	spec := CaptureSpec{ExecutableLabel: "/fixed/capture", Timeout: time.Second, StopTimeout: 10 * time.Millisecond}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for _, unsafe := range []*os.File{nil, rw, directory, pipe, char} {
		if owner, err := NewCapture(spec, code, unsafe); owner != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("unsafe stdin accepted", err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("refused constructor leaked pins", err)
	}
}

func TestCaptureCloseUncertaintyIsNeverRetriedOrReportedSuccessful(t *testing.T) {
	c, _ := captureFixture(t, "/usr/bin/cat", nil, nil)
	// Deliberate internal lifetime violation, not a provider API or raw fd close.
	if err := c.input.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if err := c.Close(context.Background()); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("uncertain release became successful", err)
		}
	}
	if !c.closed || !c.closeFailed || !c.review || c.executable != nil || c.input != nil {
		t.Fatal("release uncertainty lost")
	}
}

func TestCaptureConstructorBoundsOffsetAndInvalidFixedSpec(t *testing.T) {
	code, err := os.Open("/usr/bin/cat")
	if err != nil {
		t.Fatal(err)
	}
	defer code.Close()
	path := t.TempDir() + "/input"
	if err := os.WriteFile(path, bytes.Repeat([]byte{'x'}, MaxCaptureInput+1), 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer input.Close()
	spec := CaptureSpec{ExecutableLabel: "/fixed/capture", Timeout: time.Second, StopTimeout: 10 * time.Millisecond}
	if c, err := NewCapture(spec, code, input); c != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("oversized input accepted", err)
	}
	if err := os.Truncate(path, 2); err != nil {
		t.Fatal(err)
	}
	if _, err := input.Seek(1, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	if c, err := NewCapture(spec, code, input); c != nil || !errors.Is(err, ErrInvalid) {
		t.Fatal("nonzero shared offset accepted", err)
	}
	if _, err := input.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*CaptureSpec){
		func(s *CaptureSpec) { s.ExecutableLabel = "relative" },
		func(s *CaptureSpec) { s.ExecutableLabel = "/unclean/../path" },
		func(s *CaptureSpec) { s.Args = []string{"nul\x00argument"} },
		func(s *CaptureSpec) { s.Args = make([]string, 65) },
		func(s *CaptureSpec) { s.Timeout = 31 * time.Second },
		func(s *CaptureSpec) { s.StopTimeout = 0 },
	} {
		invalid := spec
		mutate(&invalid)
		if c, err := NewCapture(invalid, code, input); c != nil || !errors.Is(err, ErrInvalid) {
			t.Fatal("invalid fixed spec accepted", err)
		}
	}
}

func TestCapturePostExecutionDriftDiscardsReport(t *testing.T) {
	c, path := captureFixture(t, "/usr/bin/python3", nil, []byte("before"))
	// Trusted fixture mutates only its temporary regular file during the command.
	c.spec.Args = []string{"-I", "-S", "-c", "import sys; open(sys.argv[1],'w').write('after!'); print('report')", path}
	result, err := c.Capture(context.Background())
	if !zeroCapture(result) || !errors.Is(err, ErrReviewRequired) || !c.consumed || c.current != nil {
		t.Fatal("post-execution drift published evidence", err)
	}
}
