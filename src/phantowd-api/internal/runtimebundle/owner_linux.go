//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"debug/elf"
	"errors"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Owner retains a complete verified code tree and owns a private pinned process
// set. It grants no isolation, mount/storage authority or new privilege profile.
// The initial execution adapter accepts only static ELF/non-root children.
type Owner struct {
	gate      chan struct{}
	plan      *Plan
	root      *os.File
	files     map[string]*os.File
	metadata  map[string]unix.Statx_t
	processes *processowner.PinnedSet
	snapshot  OwnerSnapshot
	review    bool
	closed    bool
}

// NewOwner fixes trusted inputs and copies every process specification. Paths
// name declared executable objects inside the code tree, not the host's paths.
// No descriptors are exposed; callers can close their own root after return.
func (p *Plan) NewOwner(ctx context.Context, root *os.File, specs []processowner.MemberSpec) (*Owner, error) {
	if p == nil || len(p.files) == 0 || ctx == nil || root == nil || len(specs) == 0 || len(specs) > 8 {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	o := &Owner{gate: make(chan struct{}, 1), plan: p, files: make(map[string]*os.File, len(p.files))}
	keep := false
	defer func() {
		if !keep {
			_ = o.release()
		}
	}()
	var err error
	o.root, err = duplicateRoot(root)
	if err != nil {
		return nil, err
	}
	o.snapshot.Bundle, err = p.Inspect(ctx, o.root)
	if err != nil {
		return nil, err
	}
	o.metadata, err = o.nodeMetadata(ctx)
	if err != nil {
		return nil, err
	}
	mount := o.metadata["."].Mnt_id
	for _, expected := range p.files {
		fd, err := openBeneath(int(o.root.Fd()), expected.Path, unix.O_RDONLY)
		if err != nil {
			return nil, err
		}
		pin := os.NewFile(uintptr(fd), "retained-runtime-object")
		o.files[expected.Path] = pin
		if err := verifyOpenFile(ctx, pin, mount, expected); err != nil {
			return nil, err
		}
	}
	var executables []*os.File
	for _, spec := range specs {
		name := strings.TrimPrefix(spec.Process.Executable, "/")
		pin := o.files[name]
		credentials := spec.Process.RunAs
		if spec.Process.Executable != "/"+name || pin == nil || credentials == nil ||
			credentials.UID < 1000 || credentials.GID < 1000 || staticExecutable(pin) != nil {
			return nil, ErrInvalid
		}
		for _, group := range credentials.SupplementaryGIDs {
			if group < 1000 {
				return nil, ErrInvalid
			}
		}
		executables = append(executables, pin)
	}
	o.processes, err = processowner.NewPinnedSet(specs, executables)
	if err != nil {
		return nil, ErrInvalid
	}
	if err := o.revalidate(ctx); err != nil {
		return nil, err
	}
	o.snapshot.State = processowner.StateStopped
	keep = true
	return o, nil
}

func duplicateRoot(source *os.File) (*os.File, error) {
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	if err := raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || duplicateErr != nil || fd < 0 {
		return nil, ErrUnavailable
	}
	root := os.NewFile(uintptr(fd), "retained-runtime-root")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_PATH == 0 || flags&unix.O_DIRECTORY == 0 {
		_ = root.Close()
		return nil, ErrInvalid
	}
	return root, nil
}

// Dynamic Samba requires its separately reviewed launcher/root profile. A
// pinned entry point alone must not imply control over a host dynamic loader.
func staticExecutable(pin *os.File) error {
	program, err := elf.NewFile(pin)
	if err != nil || program.Type != elf.ET_EXEC {
		return ErrInvalid
	}
	for _, segment := range program.Progs {
		if segment.Type == elf.PT_INTERP || segment.Type == elf.PT_DYNAMIC {
			return ErrInvalid
		}
	}
	return nil
}

func (o *Owner) nodeMetadata(ctx context.Context) (map[string]unix.Statx_t, error) {
	result := make(map[string]unix.Statx_t, len(o.plan.nodes))
	for name := range o.plan.nodes {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		fd, err := openBeneath(int(o.root.Fd()), name, unix.O_PATH)
		if err != nil {
			return nil, err
		}
		var stat unix.Statx_t
		const required = unix.STATX_BASIC_STATS | unix.STATX_MNT_ID_UNIQUE
		statErr := unix.Statx(fd, "", unix.AT_EMPTY_PATH|unix.AT_NO_AUTOMOUNT, required, &stat)
		_ = unix.Close(fd)
		if statErr != nil || stat.Mask&required != required {
			return nil, ErrUnavailable
		}
		result[name] = stat
	}
	return result, nil
}

func (o *Owner) revalidate(ctx context.Context) error {
	if _, err := o.plan.Inspect(ctx, o.root); err != nil {
		return err
	}
	current, err := o.nodeMetadata(ctx)
	if err != nil {
		return err
	}
	for name, initial := range o.metadata {
		if current[name] != initial {
			return ErrMismatch
		}
	}
	for name, pin := range o.files {
		metadata, err := inspectMetadata(int(pin.Fd()), unix.S_IFREG, o.metadata["."].Mnt_id)
		if err != nil || metadata != o.metadata[name] {
			return ErrMismatch
		}
	}
	return nil
}

func (o *Owner) enter(ctx context.Context) error {
	if o == nil || o.gate == nil || ctx == nil {
		return ErrUnavailable
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case o.gate <- struct{}{}:
	default:
		return processowner.ErrBusy
	}
	if o.closed {
		<-o.gate
		return ErrUnavailable
	}
	return nil
}

func (o *Owner) Start(ctx context.Context) (OwnerSnapshot, error) {
	if err := o.enter(ctx); err != nil {
		return OwnerSnapshot{}, err
	}
	defer func() { <-o.gate }()
	if o.review {
		return o.observation(), ErrReviewRequired
	}
	if err := o.revalidate(ctx); err != nil {
		return o.quarantine(err)
	}
	processes, err := o.processes.Start(ctx)
	o.snapshot.Processes = processes
	o.snapshot.State = processes.State
	if errors.Is(err, processowner.ErrAlreadyRunning) {
		return o.observation(), err
	}
	if err != nil {
		return o.quarantine(err)
	}
	if err := o.revalidate(ctx); err != nil {
		return o.quarantine(err)
	}
	return o.observation(), nil
}

// Observe revalidates the complete roster and pinned inode identities. Drift
// stops the private process set once and permanently blocks another Start.
func (o *Owner) Observe(ctx context.Context) (OwnerSnapshot, error) {
	if err := o.enter(ctx); err != nil {
		return OwnerSnapshot{}, err
	}
	defer func() { <-o.gate }()
	if o.review {
		return o.observation(), ErrReviewRequired
	}
	if err := o.revalidate(ctx); err != nil {
		return o.quarantine(err)
	}
	processes, err := o.processes.Observe(ctx)
	o.snapshot.Processes = processes
	o.snapshot.State = processes.State
	if err != nil {
		return o.quarantine(err)
	}
	return o.observation(), nil
}

func (o *Owner) quarantine(cause error) (OwnerSnapshot, error) {
	o.review = true
	o.snapshot.State = processowner.StateReviewRequired
	processes, stopErr := o.processes.Stop(context.Background())
	o.snapshot.Processes = processes
	return o.observation(), errors.Join(ErrReviewRequired, cause, stopErr)
}

func (o *Owner) observation() OwnerSnapshot {
	result := o.snapshot
	result.Processes.Members = append([]processowner.MemberSnapshot(nil), result.Processes.Members...)
	return result
}

// Close accepts an explicit teardown and completes bounded stop even when ctx
// is canceled. Unconfirmed process ownership blocks ALL retained-input release.
// A later explicit Close can verify cleanup but never retry signals or restart.
func (o *Owner) Close(ctx context.Context) error {
	if o == nil || o.gate == nil || ctx == nil {
		return ErrUnavailable
	}
	select {
	case o.gate <- struct{}{}:
	default:
		return processowner.ErrBusy
	}
	defer func() { <-o.gate }()
	if o.closed {
		return nil
	}
	processes, stopErr := o.processes.Stop(context.Background())
	o.snapshot.Processes = processes
	if stopErr != nil {
		o.review = true
	}
	if err := o.processes.Close(); err != nil {
		o.review = true
		o.snapshot.State = processowner.StateReviewRequired
		return errors.Join(ErrReviewRequired, stopErr, err)
	}
	o.closed = true
	if o.review {
		o.snapshot.State = processowner.StateReviewRequired
		return errors.Join(ErrReviewRequired, stopErr, o.release())
	}
	o.snapshot.State = processowner.StateStopped
	return o.release()
}

func (o *Owner) release() error {
	var result error
	if o.processes != nil {
		if err := o.processes.Close(); err != nil {
			return err
		}
	}
	for _, pin := range o.files {
		result = errors.Join(result, pin.Close())
	}
	o.files = nil
	if o.root != nil {
		result = errors.Join(result, o.root.Close())
		o.root = nil
	}
	return result
}
