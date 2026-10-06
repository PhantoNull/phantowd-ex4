// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func fixture(t *testing.T, script string) (*os.File, string) {
	t.Helper()
	dir := t.TempDir()
	name := filepath.Join(dir, "input")
	if err := os.WriteFile(name, []byte("fixture-only\n"), 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(name)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	helper := filepath.Join(dir, "helper")
	if err := os.WriteFile(helper, []byte("#!/bin/sh\nset -eu\n"+script+"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	return file, helper
}

func successScript() string { return "printf '%s\\n' '" + validResult + "'" }

func TestInspectSuccess(t *testing.T) {
	t.Setenv("PHANTOWD_SHOULD_NOT_LEAK", "fixture-only")
	file, helper := fixture(t, "test \"$#\" = 0\ntest -z \"${PHANTOWD_SHOULD_NOT_LEAK-}\"\nread -r input\ntest \"$input\" = fixture-only\n"+successScript())
	result, err := inspect(context.Background(), file, helper, time.Second)
	if err != nil || result.Status != "ext-metadata" {
		t.Fatalf("inspection: %+v %v", result, err)
	}
	if _, err := file.Stat(); err != nil {
		t.Fatal("caller descriptor closed")
	}
}

func TestInspectRefusesInvalidDescriptors(t *testing.T) {
	file, helper := fixture(t, successScript())
	rw, err := os.OpenFile(file.Name(), os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer rw.Close()
	dir, err := os.Open(filepath.Dir(file.Name()))
	if err != nil {
		t.Fatal(err)
	}
	defer dir.Close()
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer read.Close()
	defer write.Close()
	pathfd, err := unix.Open(file.Name(), unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	path := os.NewFile(uintptr(pathfd), "path-only")
	defer path.Close()
	closed, err := os.Open(file.Name())
	if err != nil {
		t.Fatal(err)
	}
	closed.Close()
	for _, source := range []*os.File{nil, rw, dir, read, path, closed} {
		got, err := inspect(context.Background(), source, helper, time.Second)
		if !errors.Is(err, ErrUnsafe) || got != (Result{}) {
			t.Fatalf("unsafe input: %+v %v", got, err)
		}
	}
	if _, err := Inspect(nil, file); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Inspect(canceled, file); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestInspectProcessFailures(t *testing.T) {
	for name, script := range map[string]string{
		"nonzero":    successScript() + "\nexit 1",
		"diagnostic": "echo private-detail >&2\n" + successScript(),
		"malformed":  "echo malformed",
		"oversized":  "printf '%s' '" + strings.Repeat("x", maxOutput+1) + "'",
		"wrong-kind": strings.Replace(successScript(), "regular-image", "block-device", 1),
	} {
		t.Run(name, func(t *testing.T) {
			file, helper := fixture(t, script)
			got, err := inspect(context.Background(), file, helper, time.Second)
			if err == nil || got != (Result{}) || strings.Contains(err.Error(), "private-detail") {
				t.Fatalf("failed process: %+v %v", got, err)
			}
		})
	}
	file, _ := fixture(t, successScript())
	if _, err := inspect(context.Background(), file, "/nonexistent/phantowd-probe", time.Second); !errors.Is(err, ErrProbe) {
		t.Fatal(err)
	}
}

func TestInspectRejectsChangedObject(t *testing.T) {
	file, helper := fixture(t, successScript())
	// The supplied descriptor remains read-only, but a competing writer changes
	// the same generated file. No such writer should be possible in production.
	script := "#!/bin/sh\nprintf changed >> '" + file.Name() + "'\n" + successScript() + "\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	if got, err := inspect(context.Background(), file, helper, time.Second); !errors.Is(err, ErrUnsafe) || got != (Result{}) {
		t.Fatalf("changed input: %+v %v", got, err)
	}
}

func TestInspectDeadlineAndSingleSlot(t *testing.T) {
	file, helper := fixture(t, "exec sleep 10")
	start := time.Now()
	if got, err := inspect(context.Background(), file, helper, 80*time.Millisecond); !errors.Is(err, context.DeadlineExceeded) || got != (Result{}) {
		t.Fatalf("deadline: %+v %v", got, err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("interruptible child was not reaped promptly")
	}
	marker := filepath.Join(filepath.Dir(helper), "started")
	script := "#!/bin/sh\nprintf ready > '" + marker + "'\nexec sleep 10\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	finished := make(chan error, 1)
	go func() { _, err := inspect(ctx, file, helper, 3*time.Second); finished <- err }()
	until := time.Now().Add(2 * time.Second)
	for {
		if _, err := os.Stat(marker); err == nil {
			break
		}
		if time.Now().After(until) {
			cancel()
			<-finished
			t.Fatal("fixture did not start")
		}
		time.Sleep(time.Millisecond)
	}
	if _, err := inspect(context.Background(), file, helper, time.Second); !errors.Is(err, ErrBusy) {
		t.Fatalf("single-slot limit: %v", err)
	}
	cancel()
	if err := <-finished; !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	// A completed cancellation releases the slot for the next observation.
	file2, helper2 := fixture(t, successScript())
	if _, err := inspect(context.Background(), file2, helper2, time.Second); err != nil {
		t.Fatal(err)
	}
}

func TestBoundedOutput(t *testing.T) {
	var out boundedOutput
	if n, err := out.Write(make([]byte, maxOutput)); err != nil || n != maxOutput {
		t.Fatal(n, err)
	}
	if n, err := out.Write([]byte{1}); err == nil || n != 0 || out.Len() != maxOutput {
		t.Fatal(n, err)
	}
	var copied boundedOutput
	// Hiding the reader's WriterTo forces io.Copy to consider ReaderFrom on
	// the destination, matching the dangerous promoted-buffer method case.
	reader := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", maxOutput+1))}
	if _, err := io.Copy(&copied, reader); err == nil || copied.Len() > maxOutput {
		t.Fatal("io.Copy bypassed output limit")
	}
}
