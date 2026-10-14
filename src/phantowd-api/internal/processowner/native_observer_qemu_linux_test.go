//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestNativeObserverSenderRetainsOriginalWithoutConsumingCaller(t *testing.T) {
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(pair[0]), "fixture-receiver")
	sender := os.NewFile(uintptr(pair[1]), "fixture-sender")
	defer receiver.Close()
	defer sender.Close()
	if err := unix.SetsockoptInt(pair[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1); err != nil {
		t.Fatal(err)
	}
	pin, _, err := duplicateNativeObserverSenderQEMU(sender)
	if err != nil || pin == nil {
		t.Fatal("original sender was not retained:", err)
	}
	original, err := sender.Stat()
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := pin.Stat()
	if err != nil || !os.SameFile(original, duplicate) || pin.Fd() == sender.Fd() {
		t.Fatal("retention replaced original sender:", err)
	}
	if err := pin.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := sender.Stat(); err != nil {
		t.Fatal("private release consumed caller:", err)
	}
}

func TestNativeObserverSenderRefusesDifferentProcessCreator(t *testing.T) {
	if os.Getenv("PHANTOWD_OBSERVER_FOREIGN_CREATOR_TEST") == "1" {
		file := os.NewFile(3, "inherited-foreign-original")
		defer file.Close()
		if _, err := unix.FcntlInt(file.Fd(), unix.F_SETFD, unix.FD_CLOEXEC); err != nil {
			t.Fatal(err)
		}
		pin, identity, err := duplicateNativeObserverSenderQEMU(file)
		if pin != nil || identity != (nativeObserverSenderQEMU{}) || !errors.Is(err, ErrInvalid) {
			t.Fatal("foreign process adopted creator authority:", err)
		}
		return
	}
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	receiver := os.NewFile(uintptr(pair[0]), "original-receiver")
	sender := os.NewFile(uintptr(pair[1]), "original-sender")
	defer receiver.Close()
	defer sender.Close()
	identity, err := snapshotNativeObserverSenderQEMU(sender)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestNativeObserverSenderRefusesDifferentProcessCreator$", "-test.v")
	command.Env = []string{"PHANTOWD_OBSERVER_FOREIGN_CREATOR_TEST=1"}
	command.ExtraFiles = []*os.File{sender}
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatal("real foreign-creator subprocess:", err, string(output))
	}
	if final, err := snapshotNativeObserverSenderQEMU(sender); err != nil || final != identity {
		t.Fatal("foreign refusal changed original:", err)
	}
}

func TestNativeObserverSenderRefusesForeignRolesAndSettingsWithoutMutation(t *testing.T) {
	cases := []struct {
		name   string
		kind   int
		change func(int) error
	}{
		{"receiver credentials", unix.SOCK_SEQPACKET, func(fd int) error { return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSCRED, 1) }},
		{"pidfd ancillary", unix.SOCK_SEQPACKET, func(fd int) error { return unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSPIDFD, 1) }},
		{"nonblocking", unix.SOCK_SEQPACKET, func(fd int) error { _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFL, unix.O_NONBLOCK); return err }},
		{"inheritable controller original", unix.SOCK_SEQPACKET, func(fd int) error { _, err := unix.FcntlInt(uintptr(fd), unix.F_SETFD, 0); return err }},
		{"stream socket", unix.SOCK_STREAM, nil},
		{"datagram socket", unix.SOCK_DGRAM, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, test.kind|unix.SOCK_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			receiver := os.NewFile(uintptr(pair[0]), "negative-receiver")
			sender := os.NewFile(uintptr(pair[1]), "negative-sender")
			defer receiver.Close()
			defer sender.Close()
			if test.change != nil {
				if err := test.change(pair[1]); err != nil {
					t.Fatal(err)
				}
			}
			flags, err := unix.FcntlInt(sender.Fd(), unix.F_GETFL, 0)
			if err != nil {
				t.Fatal(err)
			}
			descriptors, err := unix.FcntlInt(sender.Fd(), unix.F_GETFD, 0)
			if err != nil {
				t.Fatal(err)
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				t.Fatal(err)
			}
			for range 8 {
				pin, identity, err := duplicateNativeObserverSenderQEMU(sender)
				if pin != nil || identity != (nativeObserverSenderQEMU{}) || !errors.Is(err, ErrInvalid) {
					t.Fatal("foreign endpoint retained:", err)
				}
			}
			after, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(before) != len(after) {
				t.Fatal("refusal leaked descriptors:", err)
			}
			finalFlags, err := unix.FcntlInt(sender.Fd(), unix.F_GETFL, 0)
			if err != nil || finalFlags != flags {
				t.Fatal("refusal repaired caller flags:", err)
			}
			finalDescriptors, err := unix.FcntlInt(sender.Fd(), unix.F_GETFD, 0)
			if err != nil || finalDescriptors != descriptors {
				t.Fatal("refusal changed caller inheritance:", err)
			}
		})
	}
	{
		pin, identity, err := duplicateNativeObserverSenderQEMU(nil)
		if pin != nil || identity != (nativeObserverSenderQEMU{}) || !errors.Is(err, ErrInvalid) {
			t.Fatal(err)
		}
	}
	plain, err := os.Open("/dev/null")
	if err != nil {
		t.Fatal(err)
	}
	defer plain.Close()
	pin, identity, err := duplicateNativeObserverSenderQEMU(plain)
	if pin != nil || identity != (nativeObserverSenderQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
}
