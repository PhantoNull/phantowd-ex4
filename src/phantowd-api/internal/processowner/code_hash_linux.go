//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"debug/elf"
	"encoding/binary"
	"errors"
	"os"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

// CodeHashReader observes retained regular files once. The trusted caller must
// independently admit the static program and compare every digest with its
// release plan; these observations grant no executable or storage authority.
// Expected program bytes come from the trusted build/release boundary, never
// by hashing the program being admitted. The caller excludes concurrent writers
// for the complete operation lifetime.
type CodeHashReader struct {
	capture *CaptureOwner
	sizes   []int64
}

type CodeHashObservation struct {
	Size   int64
	SHA256 [32]byte
}

func NewCodeHashReader(ctx context.Context, program, input *os.File, files []*os.File, expectedSHA256 [32]byte) (_ *CodeHashReader, result error) {
	if ctx == nil || len(files) < 1 || len(files) > 256 {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	c, err := NewCapture(CaptureSpec{
		ExecutableLabel: "/usr/sbin/phantowd-code-hash", Args: []string{"sha256-v1", strconv.Itoa(len(files))},
		RunAs: &Credentials{UID: 59999, GID: 59999}, Timeout: 4 * time.Second, StopTimeout: time.Second,
	}, program, input)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, c.release())
		}
	}()
	if c.inputStat.Size != 0 || c.executableDigest != expectedSHA256 {
		return nil, ErrInvalid
	}
	image, err := elf.NewFile(c.executable)
	if err != nil {
		return nil, ErrInvalid
	}
	defer image.Close()
	if image.Type != elf.ET_EXEC {
		return nil, ErrInvalid
	}
	for _, segment := range image.Progs {
		if segment.Type == elf.PT_INTERP || segment.Type == elf.PT_DYNAMIC {
			return nil, ErrInvalid
		}
	}
	r := &CodeHashReader{capture: c, sizes: make([]int64, len(files))}
	metadata := make([]unix.Stat_t, len(files))
	var total int64
	for index, source := range files {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		pin, err := duplicateReadOnlyRegular(source)
		if err != nil {
			return nil, err
		}
		c.fixtureInputs = append(c.fixtureInputs, pin)
		st := &metadata[index]
		if unix.Fstat(int(pin.Fd()), st) != nil || st.Size <= 0 || st.Size > (64<<20)-total {
			return nil, ErrInvalid
		}
		for prior := 0; prior < index; prior++ {
			if st.Dev == metadata[prior].Dev && st.Ino == metadata[prior].Ino {
				return nil, ErrInvalid
			}
		}
		r.sizes[index] = st.Size
		total += st.Size
	}
	c.fixtureInputsValid = func() bool {
		if len(c.fixtureInputs) != len(metadata) {
			return false
		}
		for index, file := range c.fixtureInputs {
			flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
			var st unix.Stat_t
			if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 ||
				unix.Fstat(int(file.Fd()), &st) != nil || !sameCaptureObject(st, metadata[index]) {
				return false
			}
		}
		return true
	}
	if !c.fixtureInputsValid() {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *CodeHashReader) Read(ctx context.Context) ([]CodeHashObservation, error) {
	if r == nil || r.capture == nil {
		return nil, ErrInvalid
	}
	if err := r.capture.enter(ctx); err != nil {
		return nil, err
	}
	defer func() { <-r.capture.gate }()
	if r.capture.closed {
		return nil, ErrUnavailable
	}
	if r.capture.review {
		return nil, ErrReviewRequired
	}
	if r.capture.consumed {
		return nil, ErrCaptureConsumed
	}
	result, err := r.capture.captureLocked(ctx)
	defer clear(result.Stdout)
	defer clear(result.Stderr)
	if err != nil {
		r.capture.review = true
		return nil, errors.Join(ErrReviewRequired, err)
	}
	if result.Kind != CaptureExited || result.ExitCode != 0 || len(result.Stderr) != 0 {
		r.capture.review = true
		return nil, ErrReviewRequired
	}
	observed, err := decodeCodeHashes(result.Stdout, r.sizes)
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		r.capture.review = true
		return nil, errors.Join(ErrReviewRequired, err)
	}
	return observed, nil
}

func (r *CodeHashReader) Settled(ctx context.Context) (bool, error) {
	if r == nil || r.capture == nil {
		return false, ErrInvalid
	}
	return r.capture.Settled(ctx)
}

func (r *CodeHashReader) Close(ctx context.Context) error {
	if r == nil || r.capture == nil {
		return ErrInvalid
	}
	return r.capture.Close(ctx)
}

func decodeCodeHashes(raw []byte, sizes []int64) ([]CodeHashObservation, error) {
	if len(sizes) < 1 || len(sizes) > 256 || len(raw) != 12+40*len(sizes) ||
		string(raw[:8]) != "PHWDHS01" || binary.LittleEndian.Uint32(raw[8:12]) != uint32(len(sizes)) {
		return nil, ErrCaptureOutput
	}
	observed := make([]CodeHashObservation, len(sizes))
	for index, size := range sizes {
		record := raw[12+40*index : 12+40*(index+1)]
		if size <= 0 || binary.LittleEndian.Uint64(record[:8]) != uint64(size) {
			return nil, ErrCaptureOutput
		}
		observed[index].Size = size
		copy(observed[index].SHA256[:], record[8:])
	}
	return observed, nil
}

func (*CodeHashReader) MarshalJSON() ([]byte, error)     { return nil, ErrInvalid }
func (*CodeHashReader) UnmarshalJSON([]byte) error       { return ErrInvalid }
func (CodeHashObservation) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*CodeHashObservation) UnmarshalJSON([]byte) error  { return ErrInvalid }
