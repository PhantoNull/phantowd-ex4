// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

// LinuxServiceGrants comes from the platform that owns the NFSD mount,
// namespaces and network exposure. Quiescent must verify client quiescence in
// that domain within the supplied context.
type LinuxServiceGrants struct {
	Address                         netip.Addr
	NFSD, Network, MountNamespace   *os.File
	ExportFS, RPCBind, Mountd, Info *os.File
	Quiescent                       func(context.Context) error
}

type managedLinux struct {
	kernel          *nfskernel.Controller
	exports         *Exports
	rpc             *RPC
	state           *runtimeState
	quiescent       func(context.Context) error
	kernelAttempted bool
}

type managedConstructionReview struct {
	constructionreview.Marker
	runtime *managedLinux
	inputs  *RetainedInputs
	cause   error
}

func (*managedConstructionReview) Error() string { return "NFS runtime construction requires review" }
func (r *managedConstructionReview) Unwrap() error {
	return errors.Join(ErrReviewRequired, r.cause)
}

// NewManagedLinux attaches enabled original inputs to one NFSv3/TCP lifetime.
// It retains independent references to the file grants and starts no services.
// The caller retains the borrowed policy and identity claims through Owner.Close.
func NewManagedLinux(ctx context.Context, inputs *RetainedInputs, grants LinuxServiceGrants) (_ *Owner, result error) {
	if err := inputs.enter(); err != nil {
		return nil, err
	}
	defer inputs.leave()
	if inputs.review {
		return nil, ErrReviewRequired
	}
	if inputs.closed || inputs.attached {
		return nil, ErrState
	}
	if ctx == nil || grants.Quiescent == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	m := &managedLinux{quiescent: grants.Quiescent}
	owner, err := newOwner(inputs.candidate, &retainedRuntime{Runtime: m, inputs: inputs})
	if err != nil || !owner.enabled {
		return nil, ErrInvalid
	}
	defer func() {
		if result == nil {
			return
		}
		cause, retained := constructionreview.Rollback(result, m.releaseUnstarted)
		if retained {
			inputs.review = true
			result = &managedConstructionReview{runtime: m, inputs: inputs, cause: cause}
		} else {
			result = cause
		}
	}()
	m.kernel, err = nfskernel.OpenLinux(ctx, grants.NFSD, grants.Network, grants.MountNamespace, grants.Address)
	if err != nil {
		return nil, fmt.Errorf("open NFSD: %w", err)
	}
	m.state, err = prepareRuntimeState(ctx)
	if err != nil {
		return nil, fmt.Errorf("prepare NFS helper state: %w", err)
	}
	m.exports, err = newExports(ctx, inputs, m.kernel, grants.Address, grants.ExportFS)
	if err != nil {
		return nil, fmt.Errorf("retain exportfs: %w", err)
	}
	m.rpc, err = NewRPC(ctx, m.kernel, grants.Address, grants.RPCBind, grants.Mountd, grants.Info)
	if err != nil {
		return nil, fmt.Errorf("retain RPC helpers: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	inputs.attached = true
	return owner, nil
}

func (m *managedLinux) releaseUnstarted() error {
	if m.rpc != nil {
		if err := m.rpc.release(); err != nil {
			return err
		}
	}
	if m.exports != nil {
		if err := m.exports.code.Close(); err != nil {
			return err
		}
	}
	if m.state != nil {
		if err := m.state.release(); err != nil {
			return err
		}
	}
	if m.kernel != nil {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		return m.kernel.Close(ctx)
	}
	return nil
}

func (m *managedLinux) Start(ctx context.Context) error {
	if err := m.state.check(ctx); err != nil {
		return err
	}
	if err := m.rpc.StartBinder(ctx); err != nil {
		return fmt.Errorf("start rpcbind: %w", err)
	}
	m.kernelAttempted = true
	if err := m.kernel.Start(ctx); err != nil {
		return fmt.Errorf("start NFSD: %w", err)
	}
	return checked(ctx, m.state.check, m.rpc.StartMountd, m.exports.Publish)
}

func (m *managedLinux) VerifyReady(ctx context.Context) error {
	return checked(ctx, m.kernel.CheckRunning, m.state.check, m.rpc.VerifyReady, m.exports.CheckPublished)
}

func (m *managedLinux) Stop(ctx context.Context) error {
	if m.kernelAttempted {
		if err := m.kernel.Stop(ctx); err != nil {
			return err
		}
	}
	return checked(ctx, m.state.check, m.exports.Withdraw, m.rpc.Stop)
}

func (m *managedLinux) VerifyStopped(ctx context.Context) error {
	checkKernel := m.kernel.CheckPrepared
	if m.kernelAttempted {
		checkKernel = m.kernel.CheckStopped
	}
	return checked(ctx, m.quiescent, checkKernel, m.state.check, m.exports.VerifyEmpty, m.rpc.VerifyStopped)
}

func (m *managedLinux) Close(ctx context.Context) error {
	return checked(ctx, m.state.check, m.exports.Close, m.rpc.Close, func(context.Context) error {
		return m.state.release()
	}, m.kernel.Close)
}
