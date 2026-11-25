//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"net"
	"os/exec"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

func TestNASBootPendingConnectionCannotLookQuiet(t *testing.T) {
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "channel"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	raw, err := l.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	check := func(want bool) {
		t.Helper()
		quiet := !want
		if err := raw.Control(func(fd uintptr) { quiet = pollQEMUNASBootFD(int(fd), 0, false) }); err != nil || quiet != want {
			t.Fatal("connection observation differs", quiet, err)
		}
	}
	check(true)
	c, err := net.DialUnix("unix", nil, l.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	check(false) // No accept: an attempted replacement connection is observable.
	if pollQEMUNASBootFD(-1, 0, false) || pollQEMUNASBootFD(-1, 0, true) {
		t.Fatal("invalid fd supplied proof")
	}
}

func TestNASBootPidfdDistinguishesLiveFromReaped(t *testing.T) {
	cmd := exec.Command("/bin/sleep", "10")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	fd, err := unix.PidfdOpen(cmd.Process.Pid, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if !pollQEMUNASBootFD(fd, 0, false) || pollQEMUNASBootFD(fd, 0, true) {
		t.Fatal("live process observed as stopped")
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	if cmd.Wait() == nil {
		t.Fatal("negative child unexpectedly exited successfully")
	}
	if !pollQEMUNASBootFD(fd, 0, true) || pollQEMUNASBootFD(fd, 0, false) {
		t.Fatal("reaped process observed as live")
	}
}
