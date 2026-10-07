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
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Owner retains a complete verified code tree and owns a private pinned process
// set. It grants no isolation, mount/storage authority or new privilege profile.
// The initial execution adapter accepts only static ELF/non-root children.
type Owner struct {
	*retainedCode
	// Fixed only by the separate disposable Samba constructor. NewOwner's
	// static/non-root contract and its inputs remain unchanged.
	configuration *retainedConfiguration
	// Inert planned daemon role: management workers retain configuration above.
	// Only the QEMU runtime can supply this second, independently derived role.
	serviceConfiguration *retainedConfiguration
	sambaState           *retainedSambaState
	gate                 chan struct{}
	processes            *processowner.PinnedSet
	snapshot             OwnerSnapshot
	review               bool
	closed               bool
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
	o := &Owner{gate: make(chan struct{}, 1)}
	keep := false
	defer func() {
		if !keep {
			_ = o.release()
		}
	}()
	var err error
	o.retainedCode, err = p.prepareRetainedCode(ctx, root)
	if err != nil {
		return nil, err
	}
	o.snapshot.Bundle = o.retainedCode.observation
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
	return o.observeLocked(ctx)
}

func (o *Owner) observeLocked(ctx context.Context) (OwnerSnapshot, error) {
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

// Supervise exclusively owns the ready lifecycle, with one complete scan after
// each fixed idle interval (1 second..1 hour). It never starts or restarts.
// Accepted cancellation stops the set; pins remain until an explicit Close.
func (o *Owner) Supervise(ctx context.Context, interval time.Duration) (OwnerSnapshot, error) {
	if interval < time.Second || interval > time.Hour {
		return OwnerSnapshot{}, ErrInvalid
	}
	if err := o.enter(ctx); err != nil {
		return OwnerSnapshot{}, err
	}
	defer func() { <-o.gate }()
	if o.review {
		return o.observation(), ErrReviewRequired
	}
	if o.snapshot.State != processowner.StateReady {
		return o.observation(), ErrInvalid
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			processes, stopErr := o.processes.Stop(context.Background())
			o.snapshot.Processes = processes
			o.snapshot.State = processes.State
			if stopErr != nil {
				o.review = true
				o.snapshot.State = processowner.StateReviewRequired
				return o.observation(), errors.Join(ctx.Err(), ErrReviewRequired, stopErr)
			}
			return o.observation(), ctx.Err()
		case <-timer.C:
			if ctx.Err() != nil {
				// A simultaneously ready timer must not begin a new scan after
				// cancellation; return through the accepted stop branch instead.
				continue
			}
			observed, err := o.observeLocked(ctx)
			if err != nil {
				return observed, err
			}
			if observed.State != processowner.StateReady {
				return o.quarantine(ErrMismatch)
			}
			// Reset only after completion: slow verification cannot accumulate
			// scans or create a burst of catch-up work.
			timer.Reset(interval)
		}
	}
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
	if o.processes != nil {
		if err := o.processes.Close(); err != nil {
			return err
		}
	}
	result := errors.Join(o.retainedCode.release(), o.configuration.release(), o.serviceConfiguration.release(), o.sambaState.release())
	o.configuration = nil
	o.serviceConfiguration = nil
	o.sambaState = nil
	return result
}

func (o *Owner) revalidate(ctx context.Context) error {
	if err := o.retainedCode.revalidate(ctx); err != nil {
		return err
	}
	if o.configuration != nil {
		if err := o.configuration.revalidate(ctx); err != nil {
			return err
		}
	}
	if o.sambaState != nil {
		if err := o.sambaState.revalidate(ctx); err != nil {
			return err
		}
	}
	if o.serviceConfiguration != nil {
		return o.serviceConfiguration.revalidate(ctx)
	}
	return nil
}
