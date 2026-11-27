// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// Runtime is trusted code that owns service resources. Its caller establishes
// the platform and controller admission before passing it here. Close may
// release runtime references only after VerifyStopped.
type Runtime interface {
	Start(context.Context) error
	VerifyReady(context.Context) error
	Stop(context.Context) error
	VerifyStopped(context.Context) error
	Close(context.Context) error
}

type retainedRuntime struct {
	Runtime
	inputs *RetainedInputs
}

// NewLinux takes the original input handle and the fixed runtime exclusively.
// The caller retains the borrowed policy and identity leases through verified
// Owner closure. On failure to construct, it retains both inputs and runtime.
func NewLinux(inputs *RetainedInputs, runtime Runtime) (*Owner, error) {
	if !validBackend(runtime) {
		return nil, ErrInvalid
	}
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
	owner, err := newOwner(inputs.candidate, &retainedRuntime{Runtime: runtime, inputs: inputs})
	if err != nil {
		return nil, err
	}
	inputs.attached = true
	return owner, nil
}

func (b *retainedRuntime) CheckInputs(ctx context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	return b.inputs.check(ctx, candidate, true)
}

func (b *retainedRuntime) Release(ctx context.Context) error {
	if err := b.Runtime.Close(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return b.inputs.close(true)
}
