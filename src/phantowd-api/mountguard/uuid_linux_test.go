// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountguard

import (
	"errors"
	"runtime"
	"testing"

	"golang.org/x/sys/unix"
)

func TestFilesystemUUIDContract(t *testing.T) {
	for _, value := range []string{"", "00000000-0000-0000-0000-000000000000", "11111111-2222-3333-4444-55555555555", "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeeG", "AAAAAAAA-bbbb-cccc-dddd-eeeeeeeeeeee", "1111111--2222-3333-4444-555555555555"} {
		if validUUID(value) {
			t.Fatal("invalid identity accepted")
		}
		if _, err := Open("/phantowd-uuid-test-not-opened", Expected{MountID: 1, RootInode: 2, FilesystemType: unix.EXT4_SUPER_MAGIC, FilesystemUUID: value}); !errors.Is(err, ErrUnsafe) {
			t.Fatal("invalid UUID did not fail before filesystem access", err)
		}
	}
	if !validUUID("11111111-2222-3333-4444-555555555555") {
		t.Fatal("canonical UUID rejected")
	}
	var reply [17]byte
	for _, length := range []byte{0, 4, 15, 17, 255} {
		reply[0] = length
		if _, err := uuidFromReply(reply); !errors.Is(err, ErrUnsupported) {
			t.Fatal("unsupported UUID width accepted", err)
		}
	}
	reply[0] = 16
	if _, err := uuidFromReply(reply); !errors.Is(err, ErrMismatch) {
		t.Fatal("zero UUID accepted", err)
	}
	for i := 1; i < len(reply); i++ {
		reply[i] = byte(i - 1)
	}
	if value, err := uuidFromReply(reply); err != nil || value != "00010203-0405-0607-0809-0a0b0c0d0e0f" {
		t.Fatal("external UUID byte order", value, err)
	}
	if _, err := filesystemUUID(-1); !errors.Is(err, ErrUnavailable) {
		t.Fatal("invalid descriptor", err)
	}
	fd, err := unix.Open("/proc", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if _, err := filesystemUUID(fd); !errors.Is(err, ErrUnsupported) {
		t.Fatal("procfs has no external filesystem UUID", err)
	}
	switch runtime.GOARCH {
	case "amd64", "386", "arm", "arm64":
		if ioctlGetFSUUID != 0x80111500 {
			t.Fatal("incorrect target ioctl ABI")
		}
	}
}
