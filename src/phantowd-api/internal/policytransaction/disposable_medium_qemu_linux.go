//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const historyExt4Root = "/run/phantowd-revisionstore-media"

type disposableMedium uint8

const (
	disposableTmpfs disposableMedium = iota
	disposableFixedExt4
)

// Closed fixture locations, never a caller-supplied path/device or product
// medium choice. Ordinary construction is permanently bound to /tmp tmpfs.
func (m disposableMedium) location() (string, int64, error) {
	switch m {
	case disposableTmpfs:
		return "/tmp", unix.TMPFS_MAGIC, nil
	case disposableFixedExt4:
		return historyExt4Root, unix.EXT4_SUPER_MAGIC, nil
	default:
		return "", 0, ErrInvalid
	}
}

func validateHistoryExt4(readOnly bool) error {
	if runtime.GOARCH != "arm" || os.Geteuid() != 0 || os.Getenv("TMPDIR") != historyExt4Root {
		return ErrUnsupported
	}
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		return ErrUnsupported
	}
	markers := 0
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_revisionstore_media_fixture=1" {
			markers++
		}
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || len(model) > 128 || strings.TrimRight(string(model), "\x00") != "ARM Versatile PB" || markers != 1 {
		return ErrUnsupported
	}
	var fs unix.Statfs_t
	var root, device unix.Stat_t
	flags := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	if readOnly {
		flags |= unix.ST_RDONLY
	}
	if unix.Statfs(historyExt4Root, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || int64(fs.Flags)&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC|unix.ST_RDONLY) != flags ||
		fs.Bsize <= 0 || fs.Blocks*uint64(fs.Bsize) > 32<<20 || fs.Blocks*uint64(fs.Bsize) < 8<<20 ||
		unix.Lstat(historyExt4Root, &root) != nil || root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Uid != 0 || root.Gid != 0 ||
		unix.Stat("/dev/sdb", &device) != nil || device.Mode&unix.S_IFMT != unix.S_IFBLK || root.Dev != device.Rdev {
		return ErrUnsupported
	}
	return nil
}
