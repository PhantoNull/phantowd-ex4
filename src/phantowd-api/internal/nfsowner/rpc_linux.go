// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// RPC owns the fixed foreground NFSv3 helpers and a retained rpcinfo probe.
// The platform owns namespace isolation, RPC port exposure and helper state.
type RPC struct {
	original                *RPC
	gate                    chan struct{}
	kernel                  *nfskernel.Controller
	address                 netip.Addr
	sets                    [2]*processowner.PinnedSet
	probe                   *os.File
	started                 int
	stopped, closed, review bool
}

type rpcConstructionReview struct {
	constructionreview.Marker
	rpc   *RPC
	cause error
}

func (*rpcConstructionReview) Error() string   { return "NFS RPC construction requires review" }
func (r *rpcConstructionReview) Unwrap() error { return r.cause }

// NewRPC borrows a controller and the three qualified executable grants.
// It starts no helper and keeps independent executable references.
func NewRPC(ctx context.Context, kernel *nfskernel.Controller, address netip.Addr, bind, mount, probe *os.File) (_ *RPC, result error) {
	if err := kernel.CheckDomain(ctx, address); err != nil {
		return nil, err
	}
	pinned, err := processowner.RetainExecutable(probe)
	if err != nil {
		return nil, err
	}
	r := &RPC{gate: make(chan struct{}, 1), kernel: kernel, address: address, probe: pinned}
	r.original = r
	defer func() {
		if result != nil {
			cause, retain := constructionreview.Rollback(result, r.release)
			if retain {
				result = &rpcConstructionReview{rpc: r, cause: cause}
			} else {
				result = cause
			}
		}
	}()
	for i, role := range []struct {
		file *os.File
		name string
		path string
		args []string
	}{
		{bind, "rpcbind", "/usr/sbin/rpcbind", []string{"-f", "-h", address.String()}},
		{mount, "mountd", "/usr/sbin/rpc.mountd", []string{"-F", "-N", "2", "-N", "4", "-V", "3", "-p", "20048"}},
	} {
		spec := processowner.Spec{Executable: role.path, Args: role.args, ReadyTimeout: 3 * time.Second,
			ProbeInterval: 50 * time.Millisecond, StopTimeout: time.Second, Ready: func(ctx context.Context) (bool, error) {
				return r.probeRole(ctx, i)
			}}
		r.sets[i], err = processowner.NewPinnedSet([]processowner.MemberSpec{{Name: role.name, Process: spec}}, []*os.File{role.file})
		if err != nil {
			return nil, err
		}
	}
	return r, nil
}

func (r *RPC) StartBinder(ctx context.Context) error { return r.start(ctx, 0) }
func (r *RPC) StartMountd(ctx context.Context) error { return r.start(ctx, 1) }

func (r *RPC) start(ctx context.Context, role int) error {
	if err := r.enter(); err != nil {
		return err
	}
	defer r.leave()
	if r.review || r.stopped || r.started != role {
		return ErrState
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	if err := r.kernel.CheckDomain(ctx, r.address); err != nil {
		return err
	}
	checkKernel := r.kernel.CheckPrepared
	if role == 1 {
		checkKernel = r.kernel.CheckRunning
	}
	if err := checkKernel(ctx); err != nil {
		return err
	}
	if snapshot, err := r.sets[role].Start(ctx); err != nil || snapshot.State != processowner.StateReady {
		r.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	r.started++
	return nil
}

func (r *RPC) probeRole(ctx context.Context, role int) (bool, error) {
	if err := r.kernel.CheckDomain(ctx, r.address); err != nil {
		return false, err
	}
	programs, versions := [2]string{"100000", "100005"}, [2]string{"4", "3"}
	command := exec.CommandContext(ctx, "/proc/self/fd/3", "-T", "tcp", r.address.String(), programs[role], versions[role])
	command.Args[0] = "/usr/bin/rpcinfo"
	command.Dir = "/"
	command.Env = []string{"LC_ALL=C"}
	command.ExtraFiles = []*os.File{r.probe}
	command.WaitDelay = time.Second
	return command.Run() == nil, ctx.Err()
}

func (r *RPC) VerifyReady(ctx context.Context) error {
	if err := r.enter(); err != nil {
		return err
	}
	defer r.leave()
	if r.started != len(r.sets) || r.stopped || r.review {
		return ErrState
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	for i, set := range r.sets {
		state, err := set.Observe(ctx)
		if err != nil || state.State != processowner.StateReady {
			r.review = true
			return errors.Join(ErrReviewRequired, err)
		}
		if ready, err := r.probeRole(ctx, i); err != nil || !ready {
			r.review = true
			return errors.Join(ErrReviewRequired, err)
		}
	}
	return nil
}

func (r *RPC) Stop(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	if err := r.enter(); err != nil {
		return err
	}
	defer r.leave()
	if r.stopped {
		return ErrState
	}
	r.stopped = true
	for i := len(r.sets) - 1; i >= 0; i-- {
		state, err := r.sets[i].Stop(ctx)
		if err != nil || state.State != processowner.StateStopped {
			r.review = true
		}
	}
	if r.review {
		return ErrReviewRequired
	}
	return nil
}

func (r *RPC) VerifyStopped(ctx context.Context) error {
	if err := r.enter(); err != nil {
		return err
	}
	defer r.leave()
	return r.verifyStopped(ctx)
}

func (r *RPC) verifyStopped(ctx context.Context) error {
	if r.review || r.started != 0 && !r.stopped {
		return ErrState
	}
	for _, set := range r.sets {
		state, err := set.Observe(ctx)
		if err != nil || state.State != processowner.StateStopped {
			return errors.Join(ErrReviewRequired, err)
		}
	}
	return nil
}

func (r *RPC) Close(ctx context.Context) error {
	if err := r.enter(); err != nil {
		return err
	}
	defer r.leave()
	if err := r.verifyStopped(ctx); err != nil {
		return err
	}
	if err := r.release(); err != nil {
		r.review = true
		return errors.Join(ErrReviewRequired, err)
	}
	r.closed = true
	return nil
}

func (r *RPC) release() error {
	for _, set := range r.sets {
		if set != nil {
			if err := set.Close(); err != nil {
				return err
			}
		}
	}
	return r.probe.Close()
}

func (r *RPC) enter() error {
	if r == nil || r.original != r {
		return ErrInvalid
	}
	select {
	case r.gate <- struct{}{}:
		if r.closed {
			r.leave()
			return ErrState
		}
		return nil
	default:
		return ErrBusy
	}
}

func (r *RPC) leave() { <-r.gate }
