// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityexec

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
	"golang.org/x/sys/unix"
)

var testAccount = serviceaccounts.Account{ID: "reader", Name: "qreader", UID: 22000, GID: 22000, State: serviceaccounts.Disabled}

func snapshot(t *testing.T, group, user bool) unixidentity.Snapshot {
	t.Helper()
	p, g := "root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\n"
	if group {
		g += "qreader:x:22000:\n"
	}
	if user {
		p += "qreader:x:22000:22000::/home/qreader:/sbin/nologin\n"
	}
	s, err := unixidentity.Parse(strings.NewReader(p), strings.NewReader(g))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func testExecutor(t *testing.T) *Executor {
	t.Helper()
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	f, st, err := pinBinary(path, uint32(os.Geteuid()))
	if err != nil {
		t.Fatal(err)
	}
	e := &Executor{expected: testAccount, binary: f, before: st, observe: func() (unixidentity.Snapshot, error) { return snapshot(t, false, false), nil }}
	e.run = func(context.Context, *os.File, []string, time.Duration) error {
		t.Fatal("unexpected command")
		return nil
	}
	t.Cleanup(func() { e.Close() })
	return e
}

func TestTypedLifecycle(t *testing.T) {
	e := testExecutor(t)
	group, user := false, false
	e.observe = func() (unixidentity.Snapshot, error) { return snapshot(t, group, user), nil }
	calls := 0
	e.run = func(ctx context.Context, f *os.File, args []string, timeout time.Duration) error {
		if ctx == nil || f != e.binary || timeout != 5*time.Second {
			t.Fatal("unsafe command supervision")
		}
		want := []string{"addgroup", "-g", "22000", "qreader"}
		if calls == 1 {
			want = []string{"adduser", "-D", "-H", "-s", "/sbin/nologin", "-G", "qreader", "-u", "22000", "qreader"}
		}
		if !reflect.DeepEqual(args, want) {
			t.Fatal("unexpected typed command vector")
		}
		if calls == 0 {
			group = true
		} else {
			user = true
		}
		calls++
		return nil
	}
	if err := e.CreateUser(context.Background(), testAccount); !errors.Is(err, ErrState) {
		t.Fatal("user without group accepted", err)
	}
	if err := e.CreateGroup(context.Background(), testAccount); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateGroup(context.Background(), testAccount); !errors.Is(err, ErrState) {
		t.Fatal("group replay accepted", err)
	}
	if err := e.CreateUser(context.Background(), testAccount); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateUser(context.Background(), testAccount); !errors.Is(err, ErrState) {
		t.Fatal("user replay accepted", err)
	}
	if calls != 2 {
		t.Fatal(calls)
	}
	if _, err := e.Observe(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := e.Close(); err != nil {
		t.Fatal(err)
	}
	if err := e.CreateGroup(context.Background(), testAccount); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
	if _, err := e.Observe(context.Background()); !errors.Is(err, ErrClosed) {
		t.Fatal(err)
	}
}

func TestRefusalAndFailureBoundaries(t *testing.T) {
	for _, scenario := range []string{"changed-binding", "enabled", "root-id", "mismatched-gid", "option-name", "nil-context", "cancelled", "observation", "zero-observation", "command", "post-observation", "post-mismatch", "post-cancel"} {
		t.Run(scenario, func(t *testing.T) {
			e := testExecutor(t)
			a := testAccount
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			calls, reads := 0, 0
			e.run = func(context.Context, *os.File, []string, time.Duration) error {
				calls++
				if scenario == "command" {
					return errors.New("private diagnostic")
				}
				return nil
			}
			e.observe = func() (unixidentity.Snapshot, error) {
				reads++
				if scenario == "post-cancel" && reads == 2 {
					cancel()
					return snapshot(t, true, false), nil
				}
				if scenario == "observation" || scenario == "post-observation" && reads == 2 {
					return unixidentity.Snapshot{}, errors.New("private source")
				}
				if scenario == "zero-observation" {
					return unixidentity.Snapshot{}, nil
				}
				return snapshot(t, false, false), nil
			}
			switch scenario {
			case "changed-binding":
				a.ID = "other"
			case "enabled":
				a.State = serviceaccounts.Enabled
			case "root-id":
				a.UID = 0
				a.GID = 0
			case "mismatched-gid":
				a.GID++
			case "option-name":
				a.Name = "-D"
			case "nil-context":
				ctx = nil
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			}
			err := e.CreateGroup(ctx, a)
			if err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("unsafe success/error", err)
			}
			want := 0
			if scenario == "command" || strings.HasPrefix(scenario, "post-") {
				want = 1
			}
			if calls != want {
				t.Fatal("dispatch count", calls, want)
			}
		})
	}
}

func TestChangedBinaryRefusedBeforeDispatch(t *testing.T) {
	for _, mode := range []os.FileMode{0600, 0720, 0700 | os.ModeSetgid} {
		path := t.TempDir() + "/binary"
		if err := os.WriteFile(path, []byte{0x7f, 'E', 'L', 'F', 0}, 0700); err != nil {
			t.Fatal(err)
		}
		f, st, err := pinBinary(path, uint32(os.Geteuid()))
		if err != nil {
			t.Fatal(err)
		}
		e := &Executor{expected: testAccount, binary: f, before: st,
			observe: func() (unixidentity.Snapshot, error) {
				t.Fatal("observed with changed executable")
				return unixidentity.Snapshot{}, nil
			},
			run: func(context.Context, *os.File, []string, time.Duration) error {
				t.Fatal("executed changed binary")
				return nil
			}}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		if err := e.CreateGroup(context.Background(), testAccount); !errors.Is(err, ErrUnsafe) {
			t.Fatal(err)
		}
		e.Close()
	}
}

func TestBusyDoesNotQueue(t *testing.T) {
	e := testExecutor(t)
	e.mu.Lock()
	if err := e.CreateGroup(context.Background(), testAccount); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	if _, err := e.Observe(context.Background()); !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
	e.mu.Unlock()
	if _, err := e.Observe(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

func TestPinnedBinaryPolicy(t *testing.T) {
	for _, scenario := range []string{"valid", "symlink", "fifo", "directory", "hardlink", "writable", "setuid", "setgid", "sticky", "not-executable", "not-elf", "small", "wrong-owner"} {
		t.Run(scenario, func(t *testing.T) {
			path := t.TempDir() + "/binary"
			if err := os.WriteFile(path, []byte{0x7f, 'E', 'L', 'F', 0}, 0700); err != nil {
				t.Fatal(err)
			}
			owner := uint32(os.Geteuid())
			switch scenario {
			case "symlink":
				if err := os.Symlink(path, path+".link"); err != nil {
					t.Fatal(err)
				}
				path += ".link"
			case "fifo":
				os.Remove(path)
				if err := unix.Mkfifo(path, 0600); err != nil {
					t.Fatal(err)
				}
			case "directory":
				path = t.TempDir()
			case "hardlink":
				if err := os.Link(path, path+".link"); err != nil {
					t.Fatal(err)
				}
			case "writable":
				os.Chmod(path, 0720)
			case "setuid":
				os.Chmod(path, 0700|os.ModeSetuid)
			case "setgid":
				os.Chmod(path, 0700|os.ModeSetgid)
			case "sticky":
				os.Chmod(path, 0700|os.ModeSticky)
			case "not-executable":
				os.Chmod(path, 0600)
			case "not-elf":
				os.WriteFile(path, []byte("#!/bin/sh\n"), 0700)
			case "small":
				os.WriteFile(path, []byte("ELF"), 0700)
			case "wrong-owner":
				owner++
			}
			f, _, err := pinBinary(path, owner)
			if f != nil {
				f.Close()
			}
			want := scenario == "valid" || scenario == "setuid" && os.Getuid() == 0 && os.Geteuid() == 0
			if (err == nil) != want {
				t.Fatal(scenario, err)
			}
		})
	}
	if _, _, err := pinBinary("relative", uint32(os.Geteuid())); err == nil {
		t.Fatal("relative path accepted")
	}
}

func TestPinnedChildSupervision(t *testing.T) {
	e := testExecutor(t)
	for _, scenario := range []string{"success", "failure", "output", "timeout"} {
		t.Run(scenario, func(t *testing.T) {
			err := runPinned(context.Background(), e.binary, []string{"-test.run=^TestExecutorChild$", "--", scenario}, 2*time.Second)
			if (err == nil) != (scenario == "success") {
				t.Fatal("unexpected child result", err)
			}
			if err != nil && err != ErrCommand {
				t.Fatal("child details leaked", err)
			}
		})
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runPinned(ctx, e.binary, nil, time.Second); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := runPinned(nil, e.binary, nil, time.Second); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}

// This helper is a Go test process, NEVER a real account-management binary.
func TestExecutorChild(t *testing.T) {
	if len(os.Args) != 4 || os.Args[2] != "--" {
		return
	}
	if os.Args[0] != "busybox" || os.Getenv("LC_ALL") != "C" || os.Getenv("PATH") != "/usr/sbin:/usr/bin:/sbin:/bin" || len(os.Environ()) != 2 || unix.Getpgrp() != os.Getpid() {
		os.Exit(90)
	}
	if cwd, err := os.Getwd(); err != nil || cwd != "/" {
		os.Exit(91)
	}
	switch os.Args[3] {
	case "success":
		os.Exit(0)
	case "failure":
		fmt.Fprint(os.Stderr, "private child diagnostic")
		os.Exit(17)
	case "output":
		fmt.Fprint(os.Stdout, strings.Repeat("x", 32768))
		os.Exit(0)
	case "timeout":
		time.Sleep(time.Minute)
		os.Exit(92)
	default:
		os.Exit(93)
	}
}
