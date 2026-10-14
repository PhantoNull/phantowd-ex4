//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// Fixed disposable opening only. No caller supplies a path, descriptor,
// credential, witness, authority or replacement client. IPC$ and data holders
// are mutually exclusive for this original lifetime.
func (s *NativePlannedServiceQEMU) StartHeldOpenFileQEMU(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed || s.review || !s.started || s.stopped || !s.dataVerified || s.heldAttempted {
		return runtimebundle.ErrReviewRequired
	}
	s.heldAttempted = true
	if err := s.verify(ctx); err != nil {
		return s.quarantine(err)
	}
	if err := s.retainPlannedOpenFileQEMU(); err != nil {
		return s.quarantine(err)
	}
	if err := s.inputs.Backend.runtime.StartPlannedFileClientQEMU(ctx); err != nil {
		s.closeErr, s.review = err, true
		s.publish()
		return errors.Join(runtimebundle.ErrReviewRequired, err)
	}
	original, err := s.inputs.Backend.ObservePlannedOpenFileQEMU(ctx)
	if err != nil {
		return s.quarantine(err)
	}
	s.heldFile = original
	if err := s.verify(ctx); err != nil {
		return s.quarantine(err)
	}
	return nil
}

func (s *NativePlannedServiceQEMU) retainPlannedOpenFileQEMU() error {
	roots, err := s.inputs.Shares.DuplicateRoots()
	if err != nil {
		return err
	}
	if len(roots) != 2 {
		err = ErrInvalid
	} else {
		for _, root := range roots {
			if root.ShareID == "writable" && !root.ReadOnly {
				fd, openErr := unix.Openat(int(root.File.Fd()), "created", unix.O_PATH|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
				if openErr != nil {
					err = openErr
					break
				}
				s.originalFile = os.NewFile(uintptr(fd), "original-planned-created-object")
				break
			}
		}
	}
	for _, root := range roots {
		if closeErr := root.File.Close(); closeErr != nil {
			s.pendingRoots, s.closeErr = roots, closeErr
			return errors.Join(err, closeErr) // No uncertain close retry/release.
		}
	}
	if err != nil {
		return err
	}
	_, err = plannedOriginalFileStatQEMU(s.originalFile)
	return err // On refusal keep the opened object through quarantine.
}

func plannedOriginalFileStatQEMU(file *os.File) (unix.Stat_t, error) {
	var stat unix.Stat_t
	if file == nil || unix.Fstat(int(file.Fd()), &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFREG ||
		stat.Uid != 2001 || stat.Gid != 2001 || stat.Nlink != 1 || stat.Dev == 0 || stat.Ino == 0 {
		return unix.Stat_t{}, runtimebundle.ErrReviewRequired
	}
	return stat, nil
}

func (s *NativePlannedServiceQEMU) verifyPlannedOriginalFileQEMU(ctx context.Context) error {
	stat, err := plannedOriginalFileStatQEMU(s.originalFile)
	if err != nil || uint64(stat.Dev) != s.heldFile.device || uint64(stat.Ino) != s.heldFile.inode {
		return runtimebundle.ErrReviewRequired
	}
	return s.inputs.Backend.VerifyPlannedOpenFileQEMU(ctx, s.heldFile)
}

// Called only AFTER verified whole runtime Close, BEFORE either original
// authority is released. A close error remains owned and is never retried.
func (s *NativePlannedServiceQEMU) closePlannedOriginalFileQEMU() error {
	if s.originalFile == nil {
		return nil
	}
	if err := s.originalFile.Close(); err != nil {
		return err
	}
	s.originalFile = nil
	return nil
}

// Retention-only observation after owned stop; no status worker, reopening,
// signal, release, authority refresh or recovery. Closed lifetimes refuse.
func (s *NativePlannedServiceQEMU) ObserveOriginalOpenFileRetainedQEMU(ctx context.Context) (bool, error) {
	if err := s.enter(ctx); err != nil {
		return false, err
	}
	defer func() { <-s.gate }()
	if s.closed || s.originalFile == nil || s.heldFile.backend == nil {
		return false, runtimebundle.ErrReviewRequired
	}
	stat, err := plannedOriginalFileStatQEMU(s.originalFile)
	if err != nil || uint64(stat.Dev) != s.heldFile.device || uint64(stat.Ino) != s.heldFile.inode {
		return false, runtimebundle.ErrReviewRequired
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	return true, nil
}
