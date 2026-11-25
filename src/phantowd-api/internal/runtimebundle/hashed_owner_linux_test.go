//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

func hashedOwnerExpected(t *testing.T, slot string) (digest [32]byte) {
	t.Helper()
	raw, err := hex.DecodeString(os.Getenv("PHANTOWD_CODE_HASH_TEST_SHA256_" + slot))
	if err != nil || len(raw) != 32 {
		t.Fatal("missing builder-owned program digest")
	}
	copy(digest[:], raw)
	return digest
}

func hashedOwnerFixture(t *testing.T, slot string) (*Plan, *os.File, *os.File, *os.File, string) {
	t.Helper()
	if os.Getenv("PHANTOWD_CODE_HASH_TEST_HELPER") == "" || os.Geteuid() != 0 {
		t.Skip("requires disposable guest with builder-bound static fixtures")
	}
	directory := t.TempDir()
	source, view := filepath.Join(directory, "source"), filepath.Join(directory, "view")
	for _, path := range []string{source, view} {
		if err := os.Mkdir(path, 0755); err != nil {
			t.Fatal(err)
		}
	}
	holder, err := os.ReadFile("/usr/sbin/phantowd-code-hash-refusal-4")
	if err != nil || sha256.Sum256(holder) != hashedOwnerExpected(t, "4") {
		t.Fatal("holder differs from builder expectation", err)
	}
	payload := []byte("independently specified owner payload\n")
	for name, data := range map[string][]byte{"holder": holder, "payload": payload} {
		mode := os.FileMode(0444)
		if name == "holder" {
			mode = 0555
		}
		if err := os.WriteFile(filepath.Join(source, name), data, mode); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("/payload", filepath.Join(source, "payload-link")); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(source, view, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(view, 0); err != nil {
			t.Error("fixture unmount", err)
		}
	})
	if err := unix.Mount("", view, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(view, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	root := os.NewFile(uintptr(fd), "sealed-owner-code")
	t.Cleanup(func() { _ = root.Close() })
	programPath := "/usr/sbin/phantowd-code-hash"
	if slot != "0" {
		programPath += "-refusal-" + slot
	}
	program, err := os.Open(programPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = program.Close() })
	emptyPath := filepath.Join(directory, "empty")
	if err := os.WriteFile(emptyPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	input, err := os.Open(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = input.Close() })
	plan, err := NewPlan([]File{
		{Path: "holder", Size: int64(len(holder)), Mode: 0555, SHA256: hashedOwnerExpected(t, "4")},
		{Path: "payload", Size: int64(len(payload)), Mode: 0444, SHA256: sha256.Sum256(payload)},
	}, []Alias{{Path: "payload-link", Target: "payload"}})
	if err != nil {
		t.Fatal(err)
	}
	return plan, root, program, input, source
}

func hashedOwnerSpecs(ready func(context.Context) (bool, error)) []processowner.MemberSpec {
	return []processowner.MemberSpec{{Name: "holder", Process: processowner.Spec{
		Executable: "/holder", RunAs: &processowner.Credentials{UID: 59999, GID: 59999}, Ready: ready,
		ReadyTimeout: time.Second, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
	}}}
}

func TestHashedOwnerRefusesAdmittedBrokenReaderBeforeServiceStart(t *testing.T) {
	plan, root, program, input, _ := hashedOwnerFixture(t, "1")
	called := false
	owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(context.Context) (bool, error) { called = true; return true, nil }), program, input, hashedOwnerExpected(t, "1"))
	if owner == nil || err != nil {
		t.Fatal("trusted stopped owner refused", err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	state, err := owner.Start(context.Background())
	if !errors.Is(err, ErrReviewRequired) || state.State != processowner.StateReviewRequired || called {
		t.Fatal("broken reader allowed service startup", err)
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("review allowed another start", err)
	}
}

func TestHashedOwnerRunsAfterCallerCloseAndStopsOnCanceledClose(t *testing.T) {
	plan, root, program, input, _ := hashedOwnerFixture(t, "0")
	owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(context.Context) (bool, error) { return true, nil }), program, input, hashedOwnerExpected(t, "0"))
	if owner == nil || err != nil {
		t.Fatal("trusted stopped owner refused", err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	for _, file := range []*os.File{root, program, input} {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	started, err := owner.Start(context.Background())
	if err != nil || started.State != processowner.StateReady || len(started.Processes.Members) != 1 {
		t.Fatal("retained owner failed startup", err)
	}
	pid := started.Processes.Members[0].Process.PID
	if pid <= 1 {
		t.Fatal("missing real service pid")
	}
	observed, err := owner.Observe(context.Background())
	if err != nil || observed.State != processowner.StateReady || observed.Processes.Members[0].Process.PID != pid {
		t.Fatal("retained owner lost service", err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := owner.Close(canceled); err != nil {
		t.Fatal("canceled close did not finish verified teardown", err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatal("owned service remains", err)
	}
	if _, err := owner.Observe(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed owner remained usable", err)
	}
}

func TestHashedOwnerStopsOnChangedBytesOrSameBytesReplacement(t *testing.T) {
	for _, kind := range []string{"bytes", "same-bytes-replacement"} {
		t.Run(kind, func(t *testing.T) {
			plan, root, program, input, source := hashedOwnerFixture(t, "0")
			readyCalls := 0
			owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(context.Context) (bool, error) { readyCalls++; return true, nil }), program, input, hashedOwnerExpected(t, "0"))
			if owner == nil || err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = owner.Close(context.Background()) })
			started, err := owner.Start(context.Background())
			if err != nil || started.State != processowner.StateReady {
				t.Fatal("startup", err)
			}
			pid := started.Processes.Members[0].Process.PID
			payloadPath := filepath.Join(source, "payload")
			data, err := os.ReadFile(payloadPath)
			if err != nil {
				t.Fatal(err)
			}
			// Mutation is confined to this test's RW alias of guest tmpfs.
			if kind == "bytes" {
				data[0] ^= 1
				if err := os.WriteFile(payloadPath, data, 0444); err != nil {
					t.Fatal(err)
				}
			} else {
				replacement := filepath.Join(source, "replacement")
				if err := os.WriteFile(replacement, data, 0444); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(replacement, payloadPath); err != nil {
					t.Fatal(err)
				}
			}
			observed, err := owner.Observe(context.Background())
			if !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired {
				t.Fatal("changed code accepted", err)
			}
			if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
				t.Fatal("changed code left service running", err)
			}
			if _, err := owner.Start(context.Background()); !errors.Is(err, ErrReviewRequired) || readyCalls != 1 {
				t.Fatal("review restarted service", err)
			}
			if err := owner.Close(context.Background()); !errors.Is(err, ErrReviewRequired) {
				t.Fatal("review was cleared", err)
			}
		})
	}
}

func TestHashedOwnerStopsOnChangedDeclaredAlias(t *testing.T) {
	plan, root, program, input, source := hashedOwnerFixture(t, "0")
	owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(context.Context) (bool, error) { return true, nil }), program, input, hashedOwnerExpected(t, "0"))
	if owner == nil || err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	started, err := owner.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pid := started.Processes.Members[0].Process.PID
	alias := filepath.Join(source, "payload-link")
	if err := os.Remove(alias); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("/holder", alias); err != nil {
		t.Fatal(err)
	}
	observed, err := owner.Observe(context.Background())
	if !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired {
		t.Fatal("changed alias accepted", err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatal("changed alias left service running", err)
	}
}

func TestHashedOwnerDeadlineStopsBeforeServiceAndRetainsReview(t *testing.T) {
	plan, root, program, input, _ := hashedOwnerFixture(t, "4")
	readyCalls := 0
	owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(context.Context) (bool, error) { readyCalls++; return true, nil }), program, input, hashedOwnerExpected(t, "4"))
	if owner == nil || err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	bounded, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	observed, err := owner.Start(bounded)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired || readyCalls != 0 {
		t.Fatal("deadline published or started service", err)
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, ErrReviewRequired) || readyCalls != 0 {
		t.Fatal("deadline retried service", err)
	}
	if err := owner.Close(context.Background()); !errors.Is(err, ErrReviewRequired) {
		t.Fatal("deadline review cleared", err)
	}
}

func TestHashedOwnerStopsOnOriginalProgramChange(t *testing.T) {
	plan, root, originalProgram, input, source := hashedOwnerFixture(t, "0")
	base := filepath.Dir(source)
	helperSource, helperView := filepath.Join(base, "helper-source"), filepath.Join(base, "helper-view")
	for _, directory := range []string{helperSource, helperView} {
		if err := os.Mkdir(directory, 0755); err != nil {
			t.Fatal(err)
		}
	}
	data, err := os.ReadFile(originalProgram.Name())
	if err != nil {
		t.Fatal(err)
	}
	writerPath := filepath.Join(helperSource, "program")
	if err := os.WriteFile(writerPath, data, 0555); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mount(helperSource, helperView, "", unix.MS_BIND, ""); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := unix.Unmount(helperView, 0); err != nil {
			t.Error("helper fixture unmount", err)
		}
	})
	if err := unix.Mount("", helperView, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		t.Fatal(err)
	}
	program, err := os.Open(filepath.Join(helperView, "program"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = program.Close() })
	owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(context.Context) (bool, error) { return true, nil }), program, input, hashedOwnerExpected(t, "0"))
	if owner == nil || err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	if err := program.Close(); err != nil {
		t.Fatal(err)
	}
	started, err := owner.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pid := started.Processes.Members[0].Process.PID
	// Only the independent RW alias of this guest-owned helper copy changes.
	writer, err := os.OpenFile(writerPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := writer.WriteAt([]byte{0}, 0); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	observed, err := owner.Observe(context.Background())
	if !errors.Is(err, ErrReviewRequired) || observed.State != processowner.StateReviewRequired {
		t.Fatal("changed helper accepted", err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatal("changed helper left service running", err)
	}
}

func TestHashedOwnerReleaseFaultKeepsRemainingAuthorityWithoutRetry(t *testing.T) {
	plan, root, program, input, _ := hashedOwnerFixture(t, "0")
	owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(context.Context) (bool, error) { return true, nil }), program, input, hashedOwnerExpected(t, "0"))
	if owner == nil || err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	started, err := owner.Start(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	pid := started.Processes.Members[0].Process.PID
	// os.File-only fault injection: never close or reuse a raw descriptor.
	if err := owner.hashProgram.program.Close(); err != nil {
		t.Fatal(err)
	}
	retainedInput := owner.hashProgram.input
	retainedCode := owner.retainedCode
	t.Cleanup(func() {
		// Discard only this synthetic fixture after proving the service is gone.
		if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
			t.Error("fixture process remains", err)
			return
		}
		_ = retainedInput.Close()
		if err := retainedCode.release(); err != nil {
			t.Error("discard fixture references", err)
		}
	})
	for attempt := 0; attempt < 2; attempt++ {
		if err := owner.Close(context.Background()); !errors.Is(err, ErrReviewRequired) || !errors.Is(err, os.ErrClosed) {
			t.Fatal("uncertain close forgotten", err)
		}
		if _, err := retainedInput.Stat(); err != nil {
			t.Fatal("later original input released", err)
		}
		if _, err := retainedCode.root.Stat(); err != nil {
			t.Fatal("code authority released", err)
		}
		if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
			t.Fatal("service not stopped before release", err)
		}
	}
}

func TestHashedOwnerConcurrentCloseCannotReleaseOriginalRoot(t *testing.T) {
	plan, root, program, input, _ := hashedOwnerFixture(t, "0")
	entered, release := make(chan struct{}), make(chan struct{})
	owner, err := plan.NewOwnerWithCodeHash(context.Background(), root, hashedOwnerSpecs(func(ctx context.Context) (bool, error) {
		close(entered)
		select {
		case <-release:
			return true, nil
		case <-ctx.Done():
			return false, ctx.Err()
		}
	}), program, input, hashedOwnerExpected(t, "0"))
	if owner == nil || err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close(context.Background()) })
	for _, file := range []*os.File{root, program, input} {
		if err := file.Close(); err != nil {
			t.Fatal(err)
		}
	}
	type result struct {
		state OwnerSnapshot
		err   error
	}
	finished := make(chan result, 1)
	go func() { state, err := owner.Start(context.Background()); finished <- result{state, err} }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("readiness not entered")
	}
	closeErr := owner.Close(context.Background())
	close(release)
	if !errors.Is(closeErr, processowner.ErrBusy) {
		t.Fatal("concurrent close passed exclusion", closeErr)
	}
	started := <-finished
	if started.err != nil || started.state.State != processowner.StateReady {
		t.Fatal("original root unavailable after concurrent close refusal", started.err)
	}
	pid := started.state.Processes.Members[0].Process.PID
	if err := owner.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := unix.Kill(pid, 0); !errors.Is(err, unix.ESRCH) {
		t.Fatal("service remains", err)
	}
}
