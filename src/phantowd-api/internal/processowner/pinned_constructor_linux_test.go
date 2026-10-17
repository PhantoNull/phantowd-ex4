//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
	"weak"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/testclosefault"
	"golang.org/x/sys/unix"
)

// Actual public factory, no process launch. A terminal subprocess makes just
// one duplicate's close return EIO. The predicted duplicate slots are validated
// by inode after construction; a changed allocation cannot silently qualify.
func TestPinnedConstructorRollbackRetainsCloseFailure(t *testing.T) {
	role := os.Getenv("PHANTOWD_PINNED_CLOSE_CHILD")
	if role == "" {
		for _, role := range []string{"outer", "readonly", "trusted", "capture"} {
			t.Run(role, func(t *testing.T) {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPinnedConstructorRollbackRetainsCloseFailure$")
				command.Env = append(os.Environ(), "PHANTOWD_PINNED_CLOSE_CHILD="+role)
				if output, err := command.CombinedOutput(); err != nil {
					t.Fatalf("terminal pinned-construction fault: %v\n%s", err, output)
				}
			})
		}
		return
	}
	if role != "outer" && role != "readonly" && role != "trusted" && role != "capture" {
		t.Fatal("unknown pinned-construction fault role")
	}
	runtime.LockOSThread()
	programPath, err := testclosefault.Executable()
	if err != nil {
		t.Fatal(err)
	}
	program, err := os.Open(programPath) // Root-owned fixture; never executed.
	if err != nil {
		t.Fatal(err)
	}
	defer program.Close()
	spec := pinnedConstructorSpec(t)
	// Warm the real factory and regular-file runtime bookkeeping before choosing
	// slots. This cannot adopt a failed lifetime or start any process.
	warm, err := NewPinnedSet([]MemberSpec{{Name: "warm", Process: spec}}, []*os.File{program})
	if err != nil || warm.Close() != nil {
		t.Fatal("ordinary constructor warmup", err)
	}
	sources := []*os.File{program, program, nil}
	if role != "outer" {
		badPath := filepath.Join(t.TempDir(), "not-executable")
		if err := os.WriteFile(badPath, []byte("fixture-only"), 0600); err != nil {
			t.Fatal(err)
		}
		flags := os.O_RDONLY
		if role == "readonly" || role == "capture" {
			flags = os.O_RDWR
		}
		bad, err := os.OpenFile(badPath, flags, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer bad.Close()
		sources = []*os.File{program, bad}
	}
	slots := pinnedConstructorSlots(t, program)
	target, expected := slots[0], program
	if role != "outer" {
		target, expected = slots[1], sources[1]
	}
	if err := testclosefault.Install(target); err != nil {
		t.Fatal("close fault install", err)
	}
	specs := make([]MemberSpec, len(sources))
	for index := range specs {
		specs[index] = MemberSpec{Name: []string{"first", "second", "third"}[index], Process: spec}
	}
	var set *PinnedSet
	var capture *CaptureOwner
	if role == "capture" {
		capture, err = NewCapture(CaptureSpec{ExecutableLabel: "/fixed/never-executed", Timeout: time.Second, StopTimeout: 100 * time.Millisecond}, program, sources[1])
	} else {
		set, err = NewPinnedSet(specs, sources)
	}
	var actual, wanted unix.Stat_t
	if unix.Fstat(target, &actual) != nil || unix.Fstat(int(expected.Fd()), &wanted) != nil ||
		actual.Dev != wanted.Dev || actual.Ino != wanted.Ino {
		t.Fatal("fault did not name the actual independent constructor duplicate")
	}
	if set != nil || capture != nil || !errors.Is(err, ErrInvalid) || !errors.Is(err, unix.EIO) || !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("pinned constructor discarded %s close uncertainty: set=%v error=%v", role, set, err)
	}
	if _, err := program.Stat(); err != nil {
		t.Fatal("construction consumed caller's executable", err)
	}
	assertPinnedConstructorReview(t, role, err)
	independent, err := NewPinnedSet([]MemberSpec{{Name: "independent", Process: spec}}, []*os.File{program})
	if err != nil || independent.Close() != nil {
		t.Fatal("local failed lifetime blocked independent construction", err)
	}
}

func assertPinnedConstructorReview(t *testing.T, role string, original error) {
	t.Helper()
	var held *constructionFailure
	if !errors.As(original, &held) {
		t.Fatal("constructor lost its opaque error handle")
	}
	wrapped := fmt.Errorf("fixture composition: %w", original)
	if role == "capture" {
		capture, ok := held.retained.(*CaptureOwner)
		if !ok || !capture.closed || !capture.review || capture.executable == nil {
			t.Fatal("capture failed construction lost original executable")
		}
		weakCapture := weak.Make(capture)
		held, capture, original = nil, nil, nil
		runtime.GC()
		runtime.GC()
		capture = weakCapture.Value()
		if capture == nil {
			t.Fatal("error did not retain the failed capture across collection")
		}
		for range 2 {
			if err := capture.Close(context.Background()); !errors.Is(err, unix.EIO) || !errors.Is(err, ErrInvalid) {
				t.Fatal("capture retried or forgot its construction causes", err)
			}
			if _, err := capture.executable.Stat(); err != nil {
				t.Fatal("capture released its unattempted executable", err)
			}
			if _, err := capture.Capture(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed capture became executable", err)
			}
		}
	} else {
		set, ok := held.retained.(*PinnedSet)
		wanted := 1
		if role == "outer" {
			wanted = 2 // First close uncertain, second duplicate never attempted.
		}
		if !ok || !set.closed || len(set.pins) != wanted || !set.set.reviewRequired {
			t.Fatal("failed set lost original/unattempted pins or review state")
		}
		weakSet := weak.Make(set)
		held, set, original = nil, nil, nil
		runtime.GC()
		runtime.GC()
		set = weakSet.Value()
		if set == nil {
			t.Fatal("error did not retain failed set across collection")
		}
		for range 2 {
			if err := set.Close(); !errors.Is(err, unix.EIO) || !errors.Is(err, ErrInvalid) {
				t.Fatal("set retried or forgot construction causes", err)
			}
			if _, err := set.pins[len(set.pins)-1].Stat(); err != nil {
				t.Fatal("set released an unattempted original", err)
			}
			if _, err := set.Start(context.Background()); !errors.Is(err, ErrUnavailable) {
				t.Fatal("failed set became executable", err)
			}
		}
	}
	runtime.KeepAlive(wrapped)
}

func pinnedConstructorSpec(t *testing.T) Spec {
	t.Helper()
	return Spec{Executable: "/fixed/never-executed", Ready: func(context.Context) (bool, error) {
		t.Fatal("constructor launched a child")
		return false, nil
	}, ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second}
}

func pinnedConstructorSlots(t *testing.T, source *os.File) [2]int {
	t.Helper()
	var slots [2]int
	for index := range slots {
		fd, err := unix.FcntlInt(source.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		slots[index] = fd
	}
	// These are raw probe descriptors, each closed once, not os.File objects or
	// released descriptors closed twice. The actual factory must reproduce them.
	for index := len(slots) - 1; index >= 0; index-- {
		if err := unix.Close(slots[index]); err != nil {
			t.Fatal(err)
		}
	}
	return slots
}
