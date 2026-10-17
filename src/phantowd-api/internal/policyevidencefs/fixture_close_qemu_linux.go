//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Fixture-only complete file-close boundary campaign. Errors are controlled,
// not kernel EIO. In after-close mode the real successful close is followed by
// an invented error and an atomically allocated duplicate at that exact FD.
// This checks that no later Close/Observe touches a recycled descriptor.
func exerciseCloseFaultMatrixQEMU(ctx context.Context, count int, factory func(int, bool) (*Observer, error)) error {
	if count < 1 || count > 6 {
		return ErrInvalid
	}
	for boundary := 0; boundary < count; boundary++ {
		for _, after := range []bool{false, true} {
			if err := ctx.Err(); err != nil {
				return err
			}
			before, err := os.ReadDir("/proc/self/fd")
			if err != nil {
				return ErrIO
			}
			a, err := factory(boundary, after)
			if err != nil {
				return err
			}
			if err := exerciseOneCloseFaultQEMU(ctx, a, count, boundary, after); err != nil {
				return err
			}
			end, err := os.ReadDir("/proc/self/fd")
			if err != nil || len(end) != len(before) {
				return ErrReview
			}
		}
	}
	return nil
}

func exerciseOneCloseFaultQEMU(ctx context.Context, a *Observer, count, boundary int, after bool) (result error) {
	if !a.valid() {
		return ErrInvalid
	}
	s := a.state
	var slots []*object
	var originals []*os.File
	for _, roster := range [][]object{s.fileObjects(), s.dirs[:]} {
		for i := len(roster) - 1; i >= 0; i-- {
			if roster[i].file != nil {
				slots = append(slots, &roster[i])
				originals = append(originals, roster[i].file)
			}
		}
	}
	if len(slots) != count || boundary < 0 || boundary >= count || s.watch < 0 {
		return ErrInvalid
	}
	closed := make(map[*os.File]bool, count)
	defer func() {
		// Only the fixture knows which controlled errors made no syscall and
		// which successful closes already ran. Never close the latter again.
		for _, file := range originals {
			if !closed[file] && file.Close() != nil {
				result = ErrReview
			}
		}
		if unix.Close(s.watch) != nil {
			result = ErrReview
		}
	}()
	stamps := make(map[*os.File]unix.Stat_t, count)
	for _, file := range originals {
		var st unix.Stat_t
		if unix.Fstat(int(file.Fd()), &st) != nil {
			return ErrIO
		}
		stamps[file] = st
	}
	canary, err := os.Open("/proc/version")
	if err != nil {
		return ErrIO
	}
	defer canary.Close()
	var canaryStat unix.Stat_t
	if unix.Fstat(int(canary.Fd()), &canaryStat) != nil {
		return ErrIO
	}
	var expected [1]byte
	if n, err := canary.ReadAt(expected[:], 0); n != 1 || err != nil {
		return ErrIO
	}
	failedFD := int(originals[boundary].Fd())
	calls := 0
	s.closeFile = func(file *os.File) error {
		index := calls
		calls++
		if index >= len(originals) || file != originals[index] {
			return ErrInvalid
		}
		if index == boundary && !after {
			return errors.New("private controlled close failure")
		}
		closed[file] = true // The underlying close is attempted exactly once.
		if err := file.Close(); err != nil {
			return err
		}
		if index == boundary {
			return errors.New("private controlled post-close failure")
		}
		return nil
	}
	if a.Close() != ErrReview || calls != boundary+1 || !s.review || !s.closeFailed || s.closed {
		return ErrReview
	}
	var replacement *os.File
	if after {
		// F_DUPFD allocates, never overwrites another owner's descriptor.
		fd, err := unix.FcntlInt(canary.Fd(), unix.F_DUPFD_CLOEXEC, failedFD)
		if err != nil {
			return ErrIO
		}
		replacement = os.NewFile(uintptr(fd), "synthetic-recycled-descriptor")
		defer replacement.Close()
		if fd != failedFD {
			return ErrReview // No exact reuse proof if another owner won it.
		}
	}
	for range 3 {
		if a.Close() != ErrReview || calls != boundary+1 {
			return ErrReview
		}
		d, err := a.Observe(ctx)
		if err != ErrReview || d.Kind() != "" {
			return ErrReview
		}
	}
	for index, slot := range slots {
		if index < boundary {
			if slot.file != nil {
				return ErrReview
			}
			continue
		}
		if slot.file != originals[index] {
			return ErrReview
		}
		if !closed[slot.file] {
			var st unix.Stat_t
			old := stamps[slot.file]
			if unix.Fstat(int(slot.file.Fd()), &st) != nil || st.Dev != old.Dev || st.Ino != old.Ino ||
				st.Mode != old.Mode || st.Uid != old.Uid || st.Gid != old.Gid || st.Size != old.Size || st.Nlink != old.Nlink {
				return ErrReview
			}
			if st.Mode&unix.S_IFMT == unix.S_IFDIR {
				probe, err := os.Open(fmt.Sprintf("/proc/self/fd/%d", slot.file.Fd()))
				if err != nil {
					return ErrIO
				}
				lockErr := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB)
				closeErr := probe.Close()
				if !errors.Is(lockErr, unix.EWOULDBLOCK) || closeErr != nil {
					return ErrReview
				}
			}
		}
	}
	if _, err := unix.FcntlInt(uintptr(s.watch), unix.F_GETFD, 0); err != nil {
		return ErrReview
	}
	if replacement != nil {
		var got [1]byte
		var st unix.Stat_t
		if unix.Fstat(int(replacement.Fd()), &st) != nil || st.Dev != canaryStat.Dev || st.Ino != canaryStat.Ino {
			return ErrReview
		}
		if n, err := replacement.ReadAt(got[:], 0); n != 1 || err != nil || got != expected {
			return ErrReview
		}
	}
	return nil
}
