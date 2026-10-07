//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

// PinnedSet privately owns independent executable descriptors and a fixed Set.
// It does not qualify a runtime closure, loader, root, credentials or manifest.
// Trusted composition must validate those inputs before construction.
type PinnedSet struct {
	gate       chan struct{}
	set        *Set
	pins       []*os.File
	closed     bool
	releaseErr error
}

// NewPinnedSet copies specs and duplicates corresponding read-only executable
// descriptors. Executable is a fixed argv[0] label, never opened by Start.
// Neither the private Set nor its descriptors are returned to consumers.
func NewPinnedSet(specs []MemberSpec, executables []*os.File) (*PinnedSet, error) {
	set, err := NewSet(specs)
	if err != nil || len(specs) != len(executables) {
		return nil, ErrInvalid
	}
	s := &PinnedSet{gate: make(chan struct{}, 1), set: set}
	keep := false
	defer func() {
		if !keep {
			_ = s.release()
		}
	}()
	for index, source := range executables {
		pin, err := duplicateExecutable(source)
		if err != nil {
			return nil, err
		}
		s.pins = append(s.pins, pin)
		set.members[index].owner.launch = func(spec Spec) (*managedProcess, error) {
			return startPinnedProcess(spec, pin)
		}
	}
	keep = true
	return s, nil
}

func duplicateExecutable(source *os.File) (*os.File, error) {
	pin, err := duplicateReadOnlyRegular(source)
	if err != nil {
		return nil, err
	}
	if trustedExecutable(pin) != nil {
		_ = pin.Close()
		return nil, ErrInvalid
	}
	return pin, nil
}

// Duplicates a regular O_RDONLY descriptor while holding the caller's file
// reference. This is retention only; callers separately qualify code or input.
func duplicateReadOnlyRegular(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	err = raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) })
	if err != nil || duplicateErr != nil || fd < 0 {
		return nil, ErrInvalid
	}
	pin := os.NewFile(uintptr(fd), "fixed-readonly-regular-input")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var stat unix.Stat_t
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 ||
		unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG {
		_ = pin.Close()
		return nil, ErrInvalid
	}
	return pin, nil
}

func (s *PinnedSet) enter(ctx context.Context) error {
	if s == nil || s.set == nil || s.gate == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.gate <- struct{}{}:
	default:
		return ErrBusy
	}
	if s.closed {
		<-s.gate
		return ErrUnavailable
	}
	return nil
}

func (s *PinnedSet) Start(ctx context.Context) (SetSnapshot, error) {
	if err := s.enter(ctx); err != nil {
		return SetSnapshot{}, err
	}
	defer func() { <-s.gate }()
	return s.set.Start(ctx)
}

func (s *PinnedSet) Observe(ctx context.Context) (SetSnapshot, error) {
	if err := s.enter(ctx); err != nil {
		return SetSnapshot{}, err
	}
	defer func() { <-s.gate }()
	return s.set.Observe(ctx)
}

func (s *PinnedSet) Stop(ctx context.Context) (SetSnapshot, error) {
	if ctx == nil {
		return SetSnapshot{}, ErrUnavailable
	}
	if err := s.enter(context.Background()); err != nil {
		return SetSnapshot{}, err
	}
	defer func() { <-s.gate }()
	return s.set.Stop(ctx)
}

// Close never signals a process. All private Owners must have confirmed their
// process groups reaped and dropped current before any executable is released.
// Explicit Stop may verify an earlier uncertain cleanup but cannot clear review.
// Descriptor-close uncertainty is different: it is permanently retained and
// never retried, even after process absence is confirmed. Failed Close does not
// imply the failed descriptor remains open; later pins are not released.
func (s *PinnedSet) Close() error {
	if s == nil || s.set == nil || s.gate == nil {
		return ErrUnavailable
	}
	select {
	case s.gate <- struct{}{}:
	default:
		return ErrBusy
	}
	defer func() { <-s.gate }()
	if s.releaseErr != nil {
		return errors.Join(ErrReviewRequired, s.releaseErr)
	}
	if s.closed {
		return nil
	}
	for _, member := range s.set.members {
		if member.owner.current != nil {
			return ErrAlreadyRunning
		}
	}
	s.closed = true
	if err := s.release(); err != nil {
		return errors.Join(ErrReviewRequired, err)
	}
	return nil
}

func (s *PinnedSet) release() error {
	if s.releaseErr != nil {
		return s.releaseErr
	}
	for len(s.pins) > 0 {
		if err := s.pins[0].Close(); err != nil {
			s.releaseErr = err
			return err
		}
		s.pins[0] = nil
		s.pins = s.pins[1:]
	}
	s.pins = nil
	return nil
}
