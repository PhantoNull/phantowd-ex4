// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

type enrollmentCore = Backend

// EnrollmentBackend uses the fixed isolated credential worker. The caller
// retains the original configuration and database roles through its lifetime.
type EnrollmentBackend struct {
	*enrollmentCore
	runner *enrollmentRunner
}

type enrollmentRunner struct {
	mu                    sync.Mutex
	configuration         *runtimebundle.SambaConfiguration
	image, private, state *os.File
	pending               *processowner.CaptureOwner
	closed, review        bool
	closeErr              error
}

// NewEnrollmentBackend binds original database directories and a confirmed
// native-lookup configuration. It prepares an offline enrollment executor
// before transferring it to the provisioned identity Owner.
func NewEnrollmentBackend(ctx context.Context, configuration *runtimebundle.SambaConfiguration,
	private, state *os.File) (outputBackend *EnrollmentBackend, result error) {
	if ctx == nil || ctx.Err() != nil || private == nil || state == nil || os.Getuid() != 0 || os.Geteuid() != 0 {
		return nil, ErrInvalid
	}
	config, err := configuration.DuplicateEnrollmentRoot(ctx)
	if err != nil {
		return nil, err
	}
	runner := &enrollmentRunner{configuration: configuration}
	backend := &EnrollmentBackend{enrollmentCore: &Backend{config: config, runner: runner}, runner: runner}
	defer func() {
		if result != nil {
			if err := backend.Close(); err != nil {
				outputBackend, result = backend, errors.Join(result, err)
			}
		}
	}()
	fd, err := unix.Openat2(unix.AT_FDCWD, "/usr/bin/phantowd-api", &unix.OpenHow{
		Flags: unix.O_RDONLY | unix.O_CLOEXEC, Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, err
	}
	runner.image = os.NewFile(uintptr(fd), "rc0-enrollment-worker")
	for i, file := range []*os.File{private, state} {
		fd, err := unix.FcntlInt(file.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			return nil, err
		}
		if i == 0 {
			runner.private = os.NewFile(uintptr(fd), "samba-private-role")
		} else {
			runner.state = os.NewFile(uintptr(fd), "samba-state-role")
		}
	}
	output, err := runner.execute(ctx, config, smbprovision.WorkerCheck, "", nil)
	clear(output)
	if err != nil {
		return nil, err
	}
	return backend, nil
}

// Disable is reserved for the session-aware service lifecycle. It must not
// change the passdb from the offline enrollment profile.
func (*EnrollmentBackend) Disable(context.Context, serviceaccounts.Account) error {
	return ErrUnavailable
}

func (*EnrollmentBackend) CanRevokeSMBSessions() bool { return false }

func (b *EnrollmentBackend) Close() error {
	if b == nil || b.runner == nil {
		return ErrInvalid
	}
	if err := b.runner.close(); err != nil {
		return err
	}
	return b.enrollmentCore.Close()
}

func (r *enrollmentRunner) Run(ctx context.Context, path string, args []string, config *os.File,
	input []byte, capture bool) ([]byte, error) {
	operation, name, err := enrollmentInvocation(path, args)
	if err != nil || capture != (operation == smbprovision.WorkerObserve) {
		return nil, ErrInvalid
	}
	output, err := r.execute(ctx, config, operation, name, input)
	if err != nil || !capture {
		clear(output)
		return nil, err
	}
	return output, nil
}

func enrollmentInvocation(path string, args []string) (string, string, error) {
	if path == pdbeditPath && slices.Equal(args, []string{"-L", "-v", "-s", configArgument}) {
		return smbprovision.WorkerObserve, "", nil
	}
	if path != smbpasswdPath || len(args) < 4 || args[len(args)-2] != configArgument {
		return "", "", ErrInvalid
	}
	name := args[len(args)-1]
	for _, operation := range []string{smbprovision.WorkerCreate, smbprovision.WorkerPassword, smbprovision.WorkerEnable} {
		_, command, err := smbprovision.WorkerCommand(operation, name)
		if err != nil {
			return "", "", ErrInvalid
		}
		if slices.Equal(args[:len(args)-2], command[1:len(command)-2]) {
			return operation, name, nil
		}
	}
	return "", "", ErrInvalid
}

func (r *enrollmentRunner) execute(ctx context.Context, original *os.File, operation, name string, input []byte) ([]byte, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if ctx == nil || ctx.Err() != nil || r.closed || r.review || r.pending != nil {
		return nil, ErrUnavailable
	}
	config, err := r.openCurrentConfiguration(ctx, original)
	if err != nil {
		return nil, err
	}
	sealed, err := smbprovision.SealWorkerInput(input)
	if err != nil {
		return nil, errors.Join(err, config.Close())
	}
	capture, err := processowner.NewSambaEnrollmentCapture(r.image, sealed, config, r.private, r.state, operation, name)
	err = errors.Join(err, config.Close(), sealed.Close())
	if err != nil {
		if capture != nil {
			err = errors.Join(err, capture.Close(context.Background()))
		}
		return nil, err
	}
	r.pending = capture
	observed, runErr := capture.Capture(ctx)
	clear(observed.Stderr)
	closeErr := capture.Close(context.Background())
	if closeErr != nil {
		r.review = true
		clear(observed.Stdout)
		return nil, runtimebundle.ErrReviewRequired
	}
	r.pending = nil
	validated, checkErr := r.openCurrentConfiguration(ctx, original)
	if validated != nil {
		checkErr = errors.Join(checkErr, validated.Close())
	}
	if runErr != nil || checkErr != nil || observed.Kind != processowner.CaptureExited || observed.ExitCode != 0 {
		r.review = true
		clear(observed.Stdout)
		return nil, ErrUnavailable
	}
	return observed.Stdout, nil
}

func (r *enrollmentRunner) openCurrentConfiguration(ctx context.Context, original *os.File) (*os.File, error) {
	config, err := r.configuration.DuplicateEnrollmentRoot(ctx)
	if err != nil {
		return nil, err
	}
	before, beforeErr := original.Stat()
	after, afterErr := config.Stat()
	if beforeErr != nil || afterErr != nil || !os.SameFile(before, after) {
		return nil, errors.Join(runtimebundle.ErrReviewRequired, config.Close())
	}
	return config, nil
}

func (r *enrollmentRunner) close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return r.closeErr
	}
	if r.pending != nil {
		if err := r.pending.Close(context.Background()); err != nil {
			return err
		}
		r.pending = nil
	}
	r.closed = true
	for _, file := range []*os.File{r.state, r.private, r.image} {
		if file != nil {
			r.closeErr = errors.Join(r.closeErr, file.Close())
		}
	}
	return r.closeErr
}
