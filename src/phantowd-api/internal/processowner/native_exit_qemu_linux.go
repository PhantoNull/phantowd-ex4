//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// RequestNativeDataExitQEMU signals only the ORIGINAL owned command, never a
// caller PID, pathname, executable or group. The trusted runtime owns single-use
// admission. attempted distinguishes irrevocable signal admission/uncertainty
// from no-effect refusal. This is NOT stop/reap, review or pin-release evidence.
func (s *PinnedSet) RequestNativeDataExitQEMU(ctx context.Context) (attempted bool, result error) {
	if err := s.enter(ctx); err != nil {
		return false, err
	}
	defer func() { <-s.gate }()
	if err := nativeDataExitFixtureGuardQEMU(); err != nil {
		return false, err
	}
	if len(s.pins) != 15 || len(s.set.members) != 1 || s.set.members[0].name != "native-samba-data" {
		return false, ErrInvalid
	}
	if err := s.set.enter(ctx); err != nil {
		return false, err
	}
	defer s.set.leave()
	if s.set.reviewRequired || s.set.state != StateReady || s.set.generation != 1 {
		return false, ErrReviewRequired
	}
	owner := s.set.members[0].owner
	if err := owner.enter(ctx); err != nil {
		return false, err
	}
	defer owner.leave()
	process := owner.current
	if owner.reviewRequired || owner.state != StateReady || owner.generation != 1 || process == nil ||
		!process.ready || process.stopAttempted || process.command == nil || process.command.Process == nil ||
		process.done == nil || process.pid <= 1 || process.command.Process.Pid != process.pid || process.exited() {
		return false, ErrReviewRequired
	}
	for _, pin := range s.pins {
		if pin == nil {
			return false, ErrReviewRequired
		}
		if _, err := pin.Stat(); err != nil {
			return false, ErrReviewRequired
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	// Do not mark this as Stop or synthesize an observed exit. Existing Wait,
	// Observe and supervised Stop must establish the actual reviewed teardown.
	return true, process.command.Process.Signal(syscall.SIGTERM)
}

func nativeDataExitFixtureGuardQEMU() error {
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrInvalid
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return ErrInvalid
	}
	line, err := os.ReadFile("/proc/cmdline")
	var fs unix.Statfs_t
	if err != nil || !strings.Contains(" "+string(line)+" ", " phantowd_samba_ext4_fixture=1 ") ||
		unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return ErrInvalid
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	parent, parentErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", os.Getppid()))
	if err != nil || parentErr != nil || self == parent {
		return ErrInvalid
	}
	return nil
}
