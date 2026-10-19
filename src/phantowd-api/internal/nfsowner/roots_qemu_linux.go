//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"golang.org/x/sys/unix"
)

// ExportRootsQEMU is a retained source lifetime, not export activation or data
// access authority. It borrows the ORIGINAL group lease and owns only its pins
// and independent O_PATH directories. No descriptor getter exists.
type ExportRootsQEMU struct{ inner *exportRoots }

type exportRoot struct {
	request  fileserviceplan.NFSExportRoot
	pin      *mountowner.VolumeRootPin
	file     *os.File
	identity unix.Statx_t
}
type exportRoots struct {
	original                       *ExportRootsQEMU
	gate                           chan struct{}
	lease                          *mountowner.MountedVolumeSetLease
	candidate                      fileserviceplan.NFSv3Candidate
	pins                           []*mountowner.VolumeRootPin
	roots                          []exportRoot
	review, closed, closeUncertain bool
}

type rootConstructionReview struct {
	constructionreview.Marker
	retained *exportRoots
	cause    error
}

func (*rootConstructionReview) Error() string        { return "NFS source construction retains review" }
func (e *rootConstructionReview) Unwrap() error      { return e.cause }
func (*rootConstructionReview) Is(target error) bool { return target == ErrReviewRequired }

// NewExportRootsQEMU requires enabled policy. Disabled NFS needs no source
// lifetime; this constructor returns ErrState without touching its lease.
// Call outside planner derivation callbacks; the storage-owner lock order and
// metadata I/O stay inside existing lease/pin methods, never kernel controls.
// On uncertain rollback retain the ORIGINAL returned error and containing lease.
func NewExportRootsQEMU(ctx context.Context, candidate fileserviceplan.NFSv3Candidate, lease *mountowner.MountedVolumeSetLease) (_ *ExportRootsQEMU, result error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	enabled, _, requests, err := candidate.Documents()
	if err != nil {
		return nil, ErrInvalid
	}
	if !enabled {
		return nil, ErrState
	}
	if lease == nil {
		return nil, ErrInvalid
	}
	o := &ExportRootsQEMU{}
	s := &exportRoots{original: o, gate: make(chan struct{}, 1), lease: lease, candidate: candidate}
	o.inner = s
	defer func() {
		if result != nil {
			cause, retained := constructionreview.Rollback(result, s.releaseInputs)
			if retained {
				result = &rootConstructionReview{retained: s, cause: cause}
			} else {
				result = cause
			}
		}
	}()
	if err := s.verifyStorage(ctx); err != nil {
		return nil, err
	}
	byVolume := map[string]*mountowner.VolumeRootPin{}
	for _, request := range requests {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		id := string(request.Volume.VolumeID)
		pin := byVolume[id]
		if pin == nil {
			pin, err = lease.PinVolumeRoot(id)
			if err != nil {
				return nil, ErrReviewRequired
			}
			byVolume[id] = pin
			s.pins = append(s.pins, pin)
		}
		file, err := pin.OpenDirectory(request.RelativePath)
		if err != nil {
			return nil, ErrReviewRequired
		}
		s.roots = append(s.roots, exportRoot{request: request, pin: pin, file: file})
		root := &s.roots[len(s.roots)-1]
		root.identity, err = observeExportRoot(file, request.Volume)
		if err != nil {
			return nil, err
		}
	}
	if err := s.verify(ctx); err != nil {
		return nil, err
	}
	return o, nil
}

func (s *exportRoots) verifyStorage(ctx context.Context) error {
	if ctx.Err() != nil {
		return errors.Join(ErrReviewRequired, ctx.Err())
	}
	evidence, err := s.lease.Verify()
	if err != nil {
		return ErrReviewRequired
	}
	snapshot, err := fileserviceplan.StorageFromMountedOwnerSet(evidence)
	if err != nil || !s.candidate.FreshAgainstStorage(snapshot) || ctx.Err() != nil {
		return ErrReviewRequired
	}
	return nil
}

func observeExportRoot(file *os.File, volume fileserviceplan.VolumeBinding) (unix.Statx_t, error) {
	var x unix.Statx_t
	if file == nil {
		return x, ErrReviewRequired
	}
	fd := int(file.Fd())
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if err != nil || flags&unix.O_PATH == 0 || flags&unix.O_DIRECTORY == 0 ||
		unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, mask, &x) != nil ||
		x.Mask&mask != mask || x.Mode&unix.S_IFMT != unix.S_IFDIR || x.Ino == 0 || x.Mnt_id == 0 ||
		x.Mnt_id != volume.MountID || x.Dev_major != volume.DeviceMajor || x.Dev_minor != volume.DeviceMinor {
		return unix.Statx_t{}, ErrReviewRequired
	}
	return x, nil
}
func sameExportRoot(a, b unix.Statx_t) bool {
	return a.Ino == b.Ino && a.Mnt_id == b.Mnt_id && a.Dev_major == b.Dev_major && a.Dev_minor == b.Dev_minor
}

func (s *exportRoots) verify(ctx context.Context) error {
	if err := s.verifyStorage(ctx); err != nil {
		return err
	}
	for i := range s.roots {
		root := &s.roots[i]
		if ctx.Err() != nil {
			return errors.Join(ErrReviewRequired, ctx.Err())
		}
		held, err := observeExportRoot(root.file, root.request.Volume)
		if err != nil || !sameExportRoot(held, root.identity) {
			return ErrReviewRequired
		}
		current, err := root.pin.OpenDirectory(root.request.RelativePath)
		if err != nil {
			return ErrReviewRequired
		}
		now, readErr := observeExportRoot(current, root.request.Volume)
		if err := current.Close(); err != nil {
			// Keep the uncertain object; never retry Close on a recycled number.
			s.roots = append(s.roots, exportRoot{file: current})
			s.closeUncertain = true
			return ErrReviewRequired
		}
		if readErr != nil || !sameExportRoot(now, root.identity) || ctx.Err() != nil {
			return ErrReviewRequired
		}
	}
	return s.verifyStorage(ctx)
}

// Check observes complete original storage and each original directory/path.
// It does not verify policy/identity freshness or authorize a service request.
func (o *ExportRootsQEMU) Check(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s, err := o.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if s.review || s.closeUncertain {
		return ErrReviewRequired
	}
	if s.closed {
		return ErrState
	}
	if err := s.verify(ctx); err != nil {
		s.review = true
		return err
	}
	return nil
}

// Close is explicit source release AFTER the containing trusted consumer's
// verified stop and copied-reference closure. It never closes the borrowed
// group lease. Review is not erased even after verified reference release.
func (o *ExportRootsQEMU) Close() error {
	s, err := o.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if err := s.releaseInputs(); err != nil {
		s.review = true
		return err
	}
	if s.review {
		return ErrReviewRequired
	}
	return nil
}
func (s *exportRoots) releaseInputs() error {
	if s.closeUncertain {
		return ErrReviewRequired
	}
	if s.closed {
		return nil
	}
	for i := range s.roots {
		if file := s.roots[i].file; file != nil {
			if file.Close() != nil {
				s.closeUncertain = true
				return ErrReviewRequired
			}
			s.roots[i].file = nil
		}
	}
	for i, pin := range s.pins {
		if pin != nil {
			if pin.Release() != nil {
				s.closeUncertain = true
				return ErrReviewRequired
			}
			s.pins[i] = nil
		}
	}
	s.closed = true
	return nil
}
func (o *ExportRootsQEMU) enter() (*exportRoots, error) {
	if o == nil || o.inner == nil || o.inner.original != o {
		return nil, ErrInvalid
	}
	s := o.inner
	select {
	case s.gate <- struct{}{}:
		return s, nil
	default:
		return nil, ErrBusy
	}
}
func (s *exportRoots) leave()                        { <-s.gate }
func (ExportRootsQEMU) MarshalJSON() ([]byte, error) { return nil, ErrPrivate }
func (*ExportRootsQEMU) UnmarshalJSON([]byte) error  { return ErrPrivate }
func (ExportRootsQEMU) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "nfs-export-roots{private}")
}
