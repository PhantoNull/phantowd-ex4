// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package smartdevice supplies a retained descriptor-generation witness only.
// It does not open paths, read disk contents or admit SMART commands.
package smartdevice

import (
	"context"
	"errors"
	"os"
	"runtime"
	"unsafe"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
	"golang.org/x/sys/unix"
)

var (
	ErrUnsafe  = errors.New("SMART descriptor generation refused")
	ErrBusy    = errors.New("SMART descriptor witness busy")
	ErrReview  = errors.New("SMART descriptor witness requires review")
	ErrClosed  = errors.New("SMART descriptor witness closed")
	ErrPrivate = errors.New("SMART descriptor witness is internal")
)

// Witness retains its own CLOEXEC duplicate. No descriptor is exposed or handed
// to a child. The caller must separately reconcile complete whole-leaf discovery,
// topology, transport support and command authority. Matching diskseq is neither
// stable media identity nor proof that a pathname still names this device.
// A caller's duplicate shares file-status flags; Check revalidates them.
type Witness struct {
	self           *Witness
	gate           chan struct{}
	file           *os.File
	expected       volumeprobe.BlockDeviceGeneration
	review, closed bool
}

// Retain borrows an already opened descriptor without changing or closing it.
// It accepts O_RDONLY block devices only, duplicates under SyscallConn.Control
// to prevent concurrent caller Close/FD reuse, then checks fstat and BLKGETDISKSEQ.
// No pathname, disk-content read, transport ioctl or capability change occurs.
// Context checkpoints do not make a kernel ioctl interruptible.
func Retain(ctx context.Context, source *os.File, expected volumeprobe.BlockDeviceGeneration) (*Witness, error) {
	if ctx == nil || source == nil || !validGeneration(expected) {
		return nil, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	connection, err := source.SyscallConn()
	if err != nil {
		return nil, ErrUnsafe
	}
	fd := -1
	var duplicateErr error
	err = connection.Control(func(original uintptr) {
		fd, duplicateErr = unix.FcntlInt(original, unix.F_DUPFD_CLOEXEC, 0)
	})
	if err != nil || duplicateErr != nil || fd < 0 {
		if fd >= 0 {
			unix.Close(fd)
		}
		return nil, ErrUnsafe
	}
	file := os.NewFile(uintptr(fd), "smart-generation-witness")
	if file == nil {
		unix.Close(fd)
		return nil, ErrUnsafe
	}
	w := &Witness{gate: make(chan struct{}, 1), file: file, expected: expected}
	w.self = w
	if !w.matches() {
		file.Close()
		return nil, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		file.Close()
		return nil, err
	}
	return w, nil
}

func validGeneration(g volumeprobe.BlockDeviceGeneration) bool {
	return (g.Major != 0 || g.Minor != 0) && g.DiskSequence != 0
}

func validObservation(stat unix.Stat_t, flags, descriptorFlags int, expected volumeprobe.BlockDeviceGeneration, sequence uint64) bool {
	return validGeneration(expected) && stat.Mode&unix.S_IFMT == unix.S_IFBLK &&
		flags&unix.O_ACCMODE == unix.O_RDONLY && flags&unix.O_PATH == 0 &&
		descriptorFlags&unix.FD_CLOEXEC != 0 &&
		unix.Major(uint64(stat.Rdev)) == expected.Major && unix.Minor(uint64(stat.Rdev)) == expected.Minor &&
		sequence != 0 && sequence == expected.DiskSequence
}

func (w *Witness) matches() bool {
	if w.file == nil {
		return false
	}
	fd := w.file.Fd()
	var stat unix.Stat_t
	if unix.Fstat(int(fd), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFBLK ||
		unix.Major(uint64(stat.Rdev)) != w.expected.Major || unix.Minor(uint64(stat.Rdev)) != w.expected.Minor {
		return false
	}
	flags, err := unix.FcntlInt(fd, unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 {
		return false
	}
	descriptorFlags, err := unix.FcntlInt(fd, unix.F_GETFD, 0)
	if err != nil || descriptorFlags&unix.FD_CLOEXEC == 0 {
		return false
	}
	var sequence uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd, uintptr(unix.BLKGETDISKSEQ), uintptr(unsafe.Pointer(&sequence)))
	runtime.KeepAlive(&sequence)
	runtime.KeepAlive(w.file)
	return errno == 0 && validObservation(stat, flags, descriptorFlags, w.expected, sequence)
}

func (w *Witness) enter(ctx context.Context) error {
	if w == nil || w.self != w || w.gate == nil || ctx == nil {
		return ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case w.gate <- struct{}{}:
		return nil
	default:
		return ErrBusy
	}
}

// Check freshly revalidates the retained FD, never a caller replacement. A failed
// kernel observation permanently enters review; restoration cannot resume it.
// Success is an instantaneous descriptor observation, not a SMART sample/lease.
func (w *Witness) Check(ctx context.Context) error {
	if err := w.enter(ctx); err != nil {
		return err
	}
	defer func() { <-w.gate }()
	if w.closed {
		return ErrClosed
	}
	if w.review {
		return ErrReview
	}
	if !w.matches() {
		w.review = true
		return ErrUnsafe
	}
	return ctx.Err()
}

// Close releases only this witness's duplicate. It has no child/transport
// ownership and is not suitable for releasing a future active capture's FD.
func (w *Witness) Close(ctx context.Context) error {
	if err := w.enter(ctx); err != nil {
		return err
	}
	defer func() { <-w.gate }()
	if w.closed {
		return nil
	}
	w.closed = true
	file := w.file
	w.file = nil
	if file == nil || file.Close() != nil {
		return ErrUnsafe
	}
	return nil
}

func (*Witness) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*Witness) UnmarshalJSON([]byte) error   { return ErrPrivate }
