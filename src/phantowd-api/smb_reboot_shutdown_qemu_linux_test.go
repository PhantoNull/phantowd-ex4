//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestQEMURebootShutdownDoesNotAcceptParentExitWithLiveDescendant(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestQEMURebootShutdownHelper$", "--", "harness", t.TempDir())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("parent/group shutdown regression: %v\n%s", err, output)
	}
}

func TestQEMURebootShutdownWaitsForCooperativeDescendant(t *testing.T) {
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.Command(executable, "-test.run=^TestQEMURebootShutdownHelper$", "--", "harness-clean", t.TempDir())
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("cooperative shutdown regression: %v\n%s", err, output)
	}
}

func TestQEMURebootShutdownRefusesUnknownOwnership(t *testing.T) {
	for _, cmd := range []*exec.Cmd{
		nil, {}, {Process: &os.Process{Pid: 1}}, {Process: &os.Process{Pid: os.Getpid()}},
		{Process: &os.Process{Pid: os.Getpid() + 1}, SysProcAttr: &syscall.SysProcAttr{Setpgid: true, Pgid: os.Getpid()}},
	} {
		if err := stopQEMURebootSamba(cmd, make(chan error)); err == nil {
			t.Fatal("unknown group accepted")
		}
	}
}

// Each subprocess uses temporary regular files and its own process group.
// The harness alone becomes a subreaper; the ordinary test runner/product does
// not. The descendant deliberately holds a file and ignores SIGTERM while its
// direct parent obeys SIGTERM. No Samba binary, mount or privilege is required.
func TestQEMURebootShutdownHelper(t *testing.T) {
	separator := -1
	for i, arg := range os.Args {
		if arg == "--" {
			separator = i
			break
		}
	}
	if separator < 0 {
		return
	}
	args := os.Args[separator+1:]
	if len(args) != 2 {
		t.Fatal("invalid shutdown helper")
	}
	mode, root := args[0], args[1]
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(root, "descendant.pid")
	switch mode {
	case "descendant", "descendant-clean":
		termination := make(chan os.Signal, 1)
		if mode == "descendant-clean" {
			signal.Notify(termination, syscall.SIGTERM)
		} else {
			signal.Ignore(syscall.SIGTERM)
		}
		file, err := os.Open(root)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if err := os.WriteFile(readyPath, []byte(strconv.Itoa(os.Getpid())), 0600); err != nil {
			t.Fatal(err)
		}
		if mode == "descendant-clean" {
			<-termination
			// Controlled descendant work outlives the direct parent. This delay
			// is test-only, not a shutdown or unmount workaround.
			time.Sleep(100 * time.Millisecond)
			if err := file.Close(); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "descendant-stopped"), []byte("closed"), 0600); err != nil {
				t.Fatal(err)
			}
			os.Exit(0)
		}
		for {
			time.Sleep(time.Hour)
		}
	case "parent", "parent-clean":
		termination := make(chan os.Signal, 1)
		signal.Notify(termination, syscall.SIGTERM)
		childMode := "descendant"
		if mode == "parent-clean" {
			childMode = "descendant-clean"
		}
		child := exec.Command(executable, "-test.run=^TestQEMURebootShutdownHelper$", "--", childMode, root)
		if err := child.Start(); err != nil {
			t.Fatal(err)
		}
		<-termination
		os.Exit(0)
	case "harness", "harness-clean":
		if err := unix.Prctl(unix.PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0); err != nil {
			t.Fatal(err)
		}
		parentMode := "parent"
		if mode == "harness-clean" {
			parentMode = "parent-clean"
		}
		parent := exec.Command(executable, "-test.run=^TestQEMURebootShutdownHelper$", "--", parentMode, root)
		parent.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
		if err := parent.Start(); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		parentFinished := make(chan struct{})
		go func() { err := parent.Wait(); close(parentFinished); done <- err }()
		childPID := 0
		childReaped := make(chan error, 1)
		defer func() {
			_ = syscall.Kill(-parent.Process.Pid, syscall.SIGKILL)
			select {
			case <-parentFinished:
			case <-time.After(2 * time.Second):
				t.Error("helper parent cleanup timed out")
				return
			}
			if childPID > 0 {
				select {
				case err := <-childReaped:
					if err != nil {
						t.Error("descendant cleanup", err)
					}
				case <-time.After(2 * time.Second):
					t.Error("descendant cleanup timed out")
				}
			}
		}()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			data, err := os.ReadFile(readyPath)
			if err == nil {
				childPID, err = strconv.Atoi(string(data))
				if err != nil || childPID <= 1 {
					t.Fatal("invalid descendant identity")
				}
				break
			}
			if !errors.Is(err, os.ErrNotExist) {
				t.Fatal(err)
			}
			time.Sleep(5 * time.Millisecond)
		}
		if childPID == 0 {
			t.Fatal("descendant did not become ready")
		}
		go func() {
			<-parentFinished
			var status syscall.WaitStatus
			_, err := syscall.Wait4(childPID, &status, 0, nil)
			childReaped <- err
		}()
		group, err := syscall.Getpgid(childPID)
		if err != nil || group != parent.Process.Pid {
			t.Fatal("descendant escaped fixture group", group, err)
		}
		stopErr := stopQEMURebootSamba(parent, done)
		alive := syscall.Kill(childPID, 0) == nil
		if mode == "harness" {
			if stopErr == nil {
				t.Fatal("cleanup accepted parent exit while descendant still held fixture file")
			}
			if alive || stopErr.Error() != "reboot Samba needed forced termination" {
				t.Fatal("forced descendant shutdown did not settle with explicit failure", stopErr, alive)
			}
		}
		if mode == "harness-clean" {
			if stopErr != nil || alive {
				t.Fatal("cooperative descendant did not settle", stopErr, alive)
			}
			if data, err := os.ReadFile(filepath.Join(root, "descendant-stopped")); err != nil || string(data) != "closed" {
				t.Fatal("success before descendant close", err)
			}
		}
		fmt.Printf("PHANTOWD_REBOOT_GROUP_READY mode=%s parent_exited=true descendant_absent=true scope=native-subprocess-only\n", mode)
	default:
		t.Fatal("unknown shutdown helper")
	}
}
