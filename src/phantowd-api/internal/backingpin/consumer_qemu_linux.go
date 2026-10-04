//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

// Fixed disposable-guest consumer, not a product entry point or LIO adapter.
// It never opens a data pathname, changes identity, executes another program,
// or creates/truncates a file. The parent owns and reaps this exact process.
func RunQEMUWritableConsumer() error {
	if runtime.GOARCH != "arm" || os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 {
		return ErrUnavailable
	}
	model, err := os.ReadFile("/proc/device-tree/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return ErrUnavailable
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 {
		return ErrUnavailable
	}
	var stat unix.Stat_t
	flags, flagErr := unix.FcntlInt(3, unix.F_GETFL, 0)
	if unix.Fstat(3, &stat) != nil || stat.Mode != unix.S_IFREG|0600 || stat.Size != 4096 || stat.Nlink != 1 || stat.Uid != 0 || stat.Gid != 0 ||
		flagErr != nil || flags&unix.O_ACCMODE != unix.O_RDWR || flags&(unix.O_PATH|unix.O_APPEND) != 0 {
		return ErrUnavailable
	}
	// PR_SET_NO_NEW_PRIVS is thread-local. Keep this thread locked through the
	// entire fixed write/hold path; do not claim a general launcher profile.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != nil {
		return ErrUnavailable
	}
	n, err := unix.Pwrite(3, []byte(writableFixtureData), 0)
	if err != nil || n != len(writableFixtureData) {
		return ErrUnavailable
	}
	// No second exec after readiness: the inherited non-root credentials stay
	// stable while the parent verifies them repeatedly and stops this process.
	time.Sleep(60 * time.Second)
	return nil
}
