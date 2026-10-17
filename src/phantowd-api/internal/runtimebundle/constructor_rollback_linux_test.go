//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"testing"
	"time"
	"weak"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/testclosefault"
	"golang.org/x/sys/unix"
)

// Install a thread-local syscall fault only in a terminal subprocess. It makes
// close of the independently duplicated constructor root return EIO WITHOUT
// closing it. No raw-close/reused-fd race, production injection or real media.
func TestConstructorRollbackRetainsRealCloseFailure(t *testing.T) {
	if os.Getenv("PHANTOWD_CONSTRUCTOR_CLOSE_CHILD") != "1" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestConstructorRollbackRetainsRealCloseFailure$")
		command.Env = append(os.Environ(), "PHANTOWD_CONSTRUCTOR_CLOSE_CHILD=1")
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("constructor close-fault subprocess: %v\n%s", err, output)
		}
		return
	}
	runtime.LockOSThread() // Never return a filtered thread to Go's thread pool.
	root := rollbackCallerRoot(t)
	plan, err := NewPlan([]File{exampleFile("bin/fixture")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := &constructorCloseContext{Context: context.Background(), t: t, caller: root}
	specs := []processowner.MemberSpec{{Name: "never-started", Process: processowner.Spec{
		Executable: "/bin/fixture", RunAs: &processowner.Credentials{UID: 1801, GID: 1800},
		Ready:        func(context.Context) (bool, error) { t.Fatal("constructor launched a child"); return false, nil },
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}
	owner, err := plan.NewOwner(ctx, root, specs)
	if ctx.target < 0 || owner != nil || !errors.Is(err, context.Canceled) ||
		!errors.Is(err, unix.EIO) || !errors.Is(err, ErrReviewRequired) {
		t.Fatalf("real constructor discarded rollback uncertainty: owner=%v target=%d error=%v", owner, ctx.target, err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("rollback consumed caller-owned root", err)
	}
	if _, err := unix.FcntlInt(uintptr(ctx.target), unix.F_GETFD, 0); err != nil {
		t.Fatal("controlled close fault unexpectedly closed the duplicated root", err)
	}
	assertConstructorReviewOwnership(t, err)
	// The filter names only the original failed descriptor; another local
	// construction can still complete a verified rollback in the same process.
	if code, err := plan.prepareRetainedCode(&constructorCancelContext{Context: context.Background()}, root); code != nil || err != context.Canceled || hasConstructionReview(err) {
		t.Fatal("local failed handle blocked independent construction", code, err)
	}
}

func assertConstructorReviewOwnership(t *testing.T, original error) {
	t.Helper()
	var outer, inner *constructionReview
	if !errors.As(original, &outer) {
		t.Fatal("constructor failure has no retained review handle")
	}
	failed, ok := outer.retained.(*Owner)
	if !ok || !failed.review || failed.snapshot.State != processowner.StateReviewRequired ||
		!errors.As(outer.cause, &inner) {
		t.Fatal("containing constructor lost the failed lifetime")
	}
	code, ok := inner.retained.(*retainedCode)
	if !ok || code.root == nil || !errors.Is(code.releaseErr, unix.EIO) {
		t.Fatal("inner constructor lost its independent root or close cause")
	}
	// A live error chain, not a finalizer or global registry, owns the failed
	// objects across collection. Pointer aliases do not gain retry authority.
	ownerWeak, codeWeak := weak.Make(failed), weak.Make(code)
	wrapped := fmt.Errorf("fixture composition: %w", original)
	original, outer, inner, failed, code = nil, nil, nil, nil, nil
	runtime.GC()
	runtime.GC()
	failed, code = ownerWeak.Value(), codeWeak.Value()
	if failed == nil || code == nil {
		t.Fatal("wrapped review did not strongly retain the original lifetimes")
	}
	for range 2 {
		if _, err := failed.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("failed constructor became startable", err)
		}
		if _, err := failed.Observe(context.Background()); !errors.Is(err, ErrReviewRequired) {
			t.Fatal("failed constructor became observable as healthy", err)
		}
		if err := failed.Close(context.Background()); !errors.Is(err, context.Canceled) || !errors.Is(err, unix.EIO) {
			t.Fatal("failed constructor forgot the original construction/close causes", err)
		}
	}
	// Test-only substitution cannot make a failed release close a new object.
	replacement := rollbackCallerRoot(t)
	code.root = replacement
	if err := code.release(); !errors.Is(err, unix.EIO) {
		t.Fatal("inner constructor retried an uncertain release", err)
	}
	if err := code.revalidate(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("partial preparation was revalidated after substitution", err)
	}
	if _, err := replacement.Stat(); err != nil {
		t.Fatal("uncertain release closed the replacement", err)
	}
	runtime.KeepAlive(wrapped)
}

func TestConstructorVerifiedRollbackReturnsOriginalCauseAndBalancesDescriptors(t *testing.T) {
	plan, err := NewPlan([]File{exampleFile("bin/fixture")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	root := rollbackCallerRoot(t)
	refuse := func() {
		t.Helper()
		ctx := &constructorCancelContext{Context: context.Background()}
		code, err := plan.prepareRetainedCode(ctx, root)
		if code != nil || err != context.Canceled || hasConstructionReview(err) {
			t.Fatal("verified rollback changed the original cause or retained a failed object", code, err)
		}
	}
	refuse()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 32 {
		refuse()
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(before) != len(after) {
		t.Fatal("verified constructor rollback leaked descriptors", len(before), len(after), err)
	}
	if _, err := root.Stat(); err != nil {
		t.Fatal("verified rollback consumed the caller root", err)
	}
}

type constructorCancelContext struct {
	context.Context
	calls int
}

func (c *constructorCancelContext) Err() error {
	c.calls++
	if c.calls >= 2 { // Preparation has already acquired its independent root.
		return context.Canceled
	}
	return nil
}

// Controlled no-child rollback boundary, not admission or real kernel EIO.
// The separate terminal subprocess above qualifies the actual constructor.
func TestConstructorNestedReviewPreservesUnattemptedContainingReferences(t *testing.T) {
	fault := releaseFaultFile(t, true)
	innerRoot := releaseFaultFile(t, false)
	code := &retainedCode{root: innerRoot, files: map[string]*os.File{"fault": fault}}
	inner := constructionRollback(context.Canceled, code, code.release)
	if !hasConstructionReview(inner) || !errors.Is(inner, os.ErrClosed) {
		t.Fatal("controlled inner rollback lost review", inner)
	}
	original, later := releaseFaultFile(t, false), releaseFaultFile(t, false)
	owner := &Owner{gate: make(chan struct{}, 1), retainedCode: &retainedCode{root: original},
		sambaState: &retainedSambaState{root: later}}
	owner.self = owner // No admitted bundle/process set or launched child.
	result := owner.constructionRollback(inner)
	if !hasConstructionReview(result) || !owner.review {
		t.Fatal("containing no-child rollback lost review", result)
	}
	for range 2 {
		if err := owner.Close(context.Background()); !errors.Is(err, os.ErrClosed) || !errors.Is(err, context.Canceled) {
			t.Fatal("containing lifetime forgot construction/cleanup causes", err)
		}
		for _, retained := range []*os.File{innerRoot, original, later} {
			if _, err := retained.Stat(); err != nil {
				t.Fatal("nested uncertainty released an unattempted original", err)
			}
		}
	}
	runtime.KeepAlive(result)
}

func rollbackCallerRoot(t *testing.T) *os.File {
	t.Helper()
	fd, err := unix.Open(t.TempDir(), unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "rollback-caller")
	t.Cleanup(func() { _ = root.Close() })
	return root
}

type constructorCloseContext struct {
	context.Context
	t      *testing.T
	caller *os.File
	calls  int
	target int
}

func (c *constructorCloseContext) Err() error {
	c.calls++
	// NewOwner checks once, preparation checks once, then Inspect checks before
	// acquiring temporary scan references. Exactly one owned duplicate exists.
	if c.calls < 3 {
		return nil
	}
	if c.calls == 3 {
		var original unix.Stat_t
		if err := unix.Fstat(int(c.caller.Fd()), &original); err != nil {
			c.t.Fatal(err)
		}
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			c.t.Fatal(err)
		}
		c.target = -1
		for _, entry := range entries {
			fd, err := strconv.Atoi(entry.Name())
			if err != nil || fd == int(c.caller.Fd()) {
				continue
			}
			var current unix.Stat_t
			flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
			if err == nil && flags&unix.O_PATH != 0 && unix.Fstat(fd, &current) == nil &&
				current.Dev == original.Dev && current.Ino == original.Ino {
				if c.target != -1 {
					c.t.Fatal("ambiguous constructor duplicate")
				}
				c.target = fd
			}
		}
		if c.target == -1 {
			c.t.Fatal("constructor did not retain an independent root")
		}
		denyConstructorClose(c.t, c.target)
	}
	return context.Canceled
}

func denyConstructorClose(t *testing.T, fd int) {
	t.Helper()
	if err := testclosefault.Install(fd); err != nil {
		t.Fatal("thread-local close fault installation", err)
	}
}
