// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountguard

import (
	"encoding/hex"
	"errors"
	"runtime"
	"strings"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux UAPI fs.h: FS_IOC_GETFSUUID = _IOR(0x15, 0, struct fsuuid2).
// fsuuid2 is exactly one length byte followed by sixteen UUID bytes. Derive
// the read-direction bits from a vendored architecture-specific _IOR value:
// FS_IOC_GET_ENCRYPTION_NONCE = _IOR('f', 27, __u8[16]). Size/type/nr shifts are the
// same on Linux architectures; the direction bits are not universally so.
// This avoids assuming the x86/ARM ioctl encoding on other host architectures.
const ioctlGetFSUUID = (unix.FS_IOC_GET_ENCRYPTION_NONCE &^ ((16 << 16) | ('f' << 8) | 27)) | (17 << 16) | (0x15 << 8)

func validUUID(value string) bool {
	if len(value) != 36 || value[8] != '-' || value[13] != '-' || value[18] != '-' || value[23] != '-' {
		return false
	}
	compact := strings.ReplaceAll(value, "-", "")
	if len(compact) != 32 || compact != strings.ToLower(compact) || compact == strings.Repeat("0", 32) {
		return false
	}
	_, err := hex.DecodeString(compact)
	return err == nil
}

func uuidFromReply(reply [17]byte) (string, error) {
	if reply[0] != 16 {
		return "", ErrUnsupported
	}
	value := hex.EncodeToString(reply[1:])
	if value == strings.Repeat("0", 32) {
		return "", ErrMismatch
	}
	return value[:8] + "-" + value[8:12] + "-" + value[12:16] + "-" + value[16:20] + "-" + value[20:], nil
}

func filesystemUUID(fd int) (string, error) {
	var reply [17]byte
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(ioctlGetFSUUID), uintptr(unsafe.Pointer(&reply[0])))
	runtime.KeepAlive(&reply)
	if errno != 0 {
		if errors.Is(errno, unix.ENOTTY) {
			return "", ErrUnsupported
		}
		return "", classify(errno)
	}
	return uuidFromReply(reply)
}

func matchRootFD(fd int, expected Expected) error {
	uuid, err := readRootUUID(fd, expected)
	if err != nil {
		return err
	}
	if uuid != expected.FilesystemUUID {
		return ErrMismatch
	}
	return nil
}

func readRootUUID(fd int, expected Expected) (string, error) {
	if err := matchFD(fd, expected, true); err != nil {
		return "", err
	}
	// ioctl does not operate on O_PATH handles. Open only "." relative to the
	// pinned root, without crossing a mount, and compare its complete identity
	// before and after the read-only ioctl. Do not use /proc/fd or reopen a name.
	readFD, err := unix.Openat2(fd, ".", &unix.OpenHow{
		Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOATIME,
		Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_XDEV | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return "", classify(err)
	}
	defer unix.Close(readFD)
	if err := matchFD(readFD, expected, true); err != nil {
		return "", err
	}
	uuid, err := filesystemUUID(readFD)
	if err != nil {
		return "", err
	}
	return uuid, matchFD(readFD, expected, true)
}
