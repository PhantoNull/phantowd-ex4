//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// This explicit profile keeps the original static/non-root service contract.
// Trusted release admission supplies the helper and its expected digest once.
// Construction launches nothing; Start/Observe perform the fixed read-only job.
// A non-nil Owner on error retains uncertain teardown authority for its caller.
func (p *Plan) NewOwnerWithCodeHash(ctx context.Context, root *os.File, specs []processowner.MemberSpec, program, input *os.File, expected [32]byte) (owner *Owner, result error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return nil, ErrInvalid
	}
	o, err := p.NewOwner(ctx, root, specs)
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, o.Close(context.Background()))
			if !o.closed || o.releaseErr != nil {
				owner = o
			}
		}
	}()
	if err := o.retainCodeHashProgram(ctx, program, input, expected); err != nil {
		return nil, err
	}
	return o, nil
}

type retainedHashProgram struct {
	program, input *os.File
	expected       [32]byte
	programStat    unix.Statx_t
	inputStat      unix.Stat_t
	pending        *processowner.CodeHashReader
	files          []*os.File
	closeErr       error
}

func duplicateHashInput(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	if err := raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || duplicateErr != nil || fd < 0 {
		return nil, ErrInvalid
	}
	pin := os.NewFile(uintptr(fd), "retained-code-hash-input")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var st unix.Stat_t
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 || unix.Fstat(fd, &st) != nil || st.Mode&unix.S_IFMT != unix.S_IFREG {
		return nil, errors.Join(ErrInvalid, pin.Close())
	}
	return pin, nil
}

func (h *retainedHashProgram) validateOriginals(ctx context.Context) error {
	if ctx == nil || h == nil || h.program == nil || h.input == nil || h.closeErr != nil {
		return ErrReviewRequired
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	program, err := inspectMetadata(int(h.program.Fd()), unix.S_IFREG, 0)
	var input unix.Stat_t
	var fs unix.Statfs_t
	if err != nil || program != h.programStat || codeNoExtendedPermissions(int(h.program.Fd())) != nil ||
		unix.Fstat(int(h.input.Fd()), &input) != nil || input.Dev != h.inputStat.Dev || input.Ino != h.inputStat.Ino ||
		input.Size != 0 || input.Mode != h.inputStat.Mode || input.Uid != 0 || input.Gid != 0 || input.Nlink != h.inputStat.Nlink ||
		input.Mtim != h.inputStat.Mtim || input.Ctim != h.inputStat.Ctim || unix.Fstatfs(int(h.input.Fd()), &fs) != nil || !localCodeFilesystem(int64(fs.Type)) {
		return ErrReviewRequired
	}
	return ctx.Err()
}

// Called only under the containing Owner gate. Unsettled children keep every
// original scan/program reference. Explicit teardown may observe absence later;
// a close error is sticky and must never cause a second close attempt.
func (h *retainedHashProgram) clearScan() error {
	if h == nil {
		return nil
	}
	if h.closeErr != nil {
		return errors.Join(ErrReviewRequired, h.closeErr)
	}
	if h.pending != nil {
		settled, err := h.pending.Settled(context.Background())
		if err != nil || !settled {
			return errors.Join(ErrReviewRequired, err)
		}
		if err := h.pending.Close(context.Background()); err != nil {
			h.closeErr = err
			return errors.Join(ErrReviewRequired, err)
		}
		h.pending = nil
	}
	for index, file := range h.files {
		if file != nil {
			if err := file.Close(); err != nil {
				h.closeErr = err
				return errors.Join(ErrReviewRequired, err)
			}
			h.files[index] = nil
		}
	}
	h.files = nil
	return nil
}

func (h *retainedHashProgram) release() error {
	if h == nil {
		return nil
	}
	if err := h.clearScan(); err != nil {
		return err
	}
	for _, file := range []*os.File{h.program, h.input} {
		if file != nil {
			if err := file.Close(); err != nil {
				h.closeErr = err
				return errors.Join(ErrReviewRequired, err)
			}
		}
	}
	h.program, h.input = nil, nil
	return nil
}

func (o *Owner) revalidateCode(ctx context.Context) error {
	if o.hashProgram == nil {
		return o.retainedCode.revalidate(ctx)
	}
	return o.retainedCode.revalidateWithCodeHash(ctx, o.hashProgram)
}

// Unlike Plan.Inspect, this explicitly selected service operation may launch
// the retained read-only helper. All original census/digest/identity fences stay.
func (c *retainedCode) revalidateWithCodeHash(ctx context.Context, h *retainedHashProgram) (result error) {
	if c == nil || c.root == nil || c.plan == nil || len(c.files) != len(c.plan.files) || len(c.metadata) != len(c.plan.nodes) {
		return ErrUnavailable
	}
	if h.pending != nil || len(h.files) != 0 {
		return ErrReviewRequired
	}
	if err := h.validateOriginals(ctx); err != nil {
		return err
	}
	// The containing exclusion gate keeps this private original alive. No
	// transient root reference can escape the retained close barrier.
	defer func() { result = errors.Join(result, h.clearScan()) }()
	fd := int(c.root.Fd())
	initial, err := c.plan.inspectShape(ctx, fd)
	if err != nil {
		return err
	}
	metadata := make([]unix.Statx_t, len(c.plan.files))
	for index, expected := range c.plan.files {
		if err := ctx.Err(); err != nil {
			return err
		}
		fileFD, err := openBeneath(fd, expected.Path, unix.O_RDONLY)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fileFD), "owned-code-hash-scan")
		h.files = append(h.files, file)
		metadata[index], err = inspectMetadata(fileFD, unix.S_IFREG, initial.Mnt_id)
		before := metadata[index]
		if err != nil || before.Size != uint64(expected.Size) || uint32(before.Mode&07777) != expected.Mode || before.Nlink != 1 {
			return ErrMismatch
		}
		if err := codeNoExtendedPermissions(fileFD); err != nil {
			return err
		}
	}
	h.pending, err = processowner.NewCodeHashReader(ctx, h.program, h.input, h.files, h.expected)
	if err != nil {
		return err
	}
	observed, err := h.pending.Read(ctx)
	if err != nil {
		return errors.Join(ErrReviewRequired, err)
	}
	if len(observed) != len(c.plan.files) {
		return ErrMismatch
	}
	for index, expected := range c.plan.files {
		after, err := inspectMetadata(int(h.files[index].Fd()), unix.S_IFREG, initial.Mnt_id)
		if err != nil || after != metadata[index] || observed[index].Size != expected.Size || observed[index].SHA256 != expected.SHA256 {
			return ErrMismatch
		}
	}
	final, err := inspectMetadata(fd, unix.S_IFDIR, 0)
	if err != nil || final != initial {
		return ErrMismatch
	}
	if err := h.validateOriginals(ctx); err != nil {
		return err
	}
	return c.verifyRetainedIdentities(ctx)
}

// Construction-only binding, shared by explicitly selected service profiles.
// No public operation can select a backend or replace this retained resource.
func (o *Owner) retainCodeHashProgram(ctx context.Context, program, input *os.File, expected [32]byte) error {
	if o == nil || o.retainedCode == nil || o.processes == nil || o.hashProgram != nil || o.closed || o.review ||
		o.snapshot.State != processowner.StateStopped || o.snapshot.Processes.Generation != 0 ||
		os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return ErrInvalid
	}
	var err error
	h := &retainedHashProgram{expected: expected}
	o.hashProgram = h
	for index, source := range []*os.File{program, input} {
		pin, err := duplicateHashInput(source)
		if err != nil {
			return err
		}
		if index == 0 {
			h.program = pin
		} else {
			h.input = pin
		}
	}
	h.programStat, err = inspectMetadata(int(h.program.Fd()), unix.S_IFREG, 0)
	if err != nil || h.programStat.Nlink != 1 || codeNoExtendedPermissions(int(h.program.Fd())) != nil ||
		unix.Fstat(int(h.input.Fd()), &h.inputStat) != nil {
		return ErrInvalid
	}
	files := make([]*os.File, len(o.plan.files))
	for index, expected := range o.plan.files {
		files[index] = o.files[expected.Path]
	}
	h.pending, err = processowner.NewCodeHashReader(ctx, h.program, h.input, files, expected)
	if err != nil {
		return err
	}
	if err := h.clearScan(); err != nil {
		return err
	}
	// Keep the complete original late fence after fixing the additional inputs.
	if err := o.retainedCode.revalidate(ctx); err != nil {
		return err
	}
	if err := h.validateOriginals(ctx); err != nil {
		return err
	}
	return nil
}
