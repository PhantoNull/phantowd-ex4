//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
)

var pendingOwnerInputLossAttemptedQEMU atomic.Bool

// Keep the reviewed Owner reachable until this disposable process exits. A
// successful fixture must not release reviewed originals to manufacture equality.
var pendingOwnerInputLossRetainedQEMU *pendingClientOwnerQEMU

type pendingInputLossCodeRefsQEMU struct {
	code  *retainedCode
	root  *os.File
	files map[string]*os.File
}

type pendingInputLossPinQEMU struct {
	file *os.File
	info os.FileInfo
}

// ProbePendingClientOwnerInputLossQEMU is a fixed constructor-only disposable
// guest fault. It exposes no descriptor, backend, launch or product authority.
func (p *Plan) ProbePendingClientOwnerInputLossQEMU(ctx context.Context, bootstrap *Plan, clientRoot, bootstrapRoot *os.File) (result error) {
	if err := sambaCodeFixtureGuard(); err != nil {
		return err
	}
	if ctx == nil || p == nil || bootstrap == nil || clientRoot == nil || bootstrapRoot == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !pendingOwnerInputLossAttemptedQEMU.CompareAndSwap(false, true) {
		return ErrReviewRequired
	}
	owner, err := newPendingClientOwnerQEMU(ctx, p, bootstrap, clientRoot, bootstrapRoot, []byte("qemu-only-not-a-credential"))
	pendingOwnerInputLossRetainedQEMU = owner
	if err != nil {
		return err // Any partially retained Owner also survives until disposal.
	}
	if owner == nil || owner.inputs == nil || owner.inputs.client == nil || owner.inputs.bootstrap == nil {
		return ErrMismatch
	}
	if err := owner.inputs.revalidate(ctx); err != nil {
		return err
	}
	inputs, adapter := owner.inputs, owner.clientLifecycleQEMU()
	lost := inputs.client.files[pendingClientProgramQEMU]
	if lost == nil || adapter == nil || owner.started || owner.closed || owner.review {
		return ErrMismatch
	}
	var codes [2]pendingInputLossCodeRefsQEMU
	var pins []pendingInputLossPinQEMU
	for index, code := range []*retainedCode{inputs.client, inputs.bootstrap} {
		if code == nil || code.root == nil {
			return ErrMismatch
		}
		codes[index] = pendingInputLossCodeRefsQEMU{code: code, root: code.root, files: make(map[string]*os.File, len(code.files))}
		info, err := code.root.Stat()
		if err != nil {
			return err
		}
		pins = append(pins, pendingInputLossPinQEMU{file: code.root, info: info})
		for name, pin := range code.files {
			info, err := pin.Stat()
			if err != nil {
				return err
			}
			codes[index].files[name] = pin
			if pin != lost {
				pins = append(pins, pendingInputLossPinQEMU{file: pin, info: info})
			}
		}
	}
	// Close the owned object normally, never its raw numeric FD. It must not
	// later close a different independently owned descriptor if the slot recycles.
	if err := lost.Close(); err != nil {
		return err
	}
	unrelated, err := duplicateRoot(clientRoot)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unrelated.Close()) }()
	unrelatedInfo, err := unrelated.Stat()
	if err != nil {
		return err
	}
	firstErr := owner.close()
	if !errors.Is(firstErr, ErrReviewRequired) || !errors.Is(firstErr, ErrMismatch) || !owner.review || owner.started || owner.closed {
		return errors.Join(ErrMismatch, firstErr)
	}
	firstCause := owner.reviewCause
	if firstCause == nil || !errors.Is(firstErr, firstCause) {
		return ErrMismatch
	}
	checkUnattempted := func() error {
		if owner.inputs != inputs || inputs.client != codes[0].code || inputs.bootstrap != codes[1].code || owner.clientLifecycleQEMU() != adapter {
			return ErrMismatch
		}
		for _, saved := range codes {
			if saved.code.root != saved.root || len(saved.code.files) != len(saved.files) {
				return ErrMismatch
			}
			for name, original := range saved.files {
				if saved.code.files[name] != original {
					return ErrMismatch
				}
			}
		}
		for _, saved := range pins {
			info, err := saved.file.Stat()
			if err != nil || !os.SameFile(saved.info, info) {
				return errors.Join(ErrMismatch, err)
			}
		}
		if _, err := lost.Stat(); err == nil {
			return ErrMismatch // A new open is never restoration of the lost pin.
		}
		info, err := unrelated.Stat()
		if err != nil || !os.SameFile(unrelatedInfo, info) {
			return errors.Join(ErrMismatch, err)
		}
		return nil
	}
	if err := checkUnattempted(); err != nil {
		return errors.Join(firstErr, err)
	}
	reviewFDs, err := retainedFixtureFDCount()
	if err != nil {
		return errors.Join(firstErr, err)
	}
	for range 2 {
		for _, refusal := range []error{owner.close(), owner.start(ctx), owner.closeClient(ctx)} {
			if !errors.Is(refusal, ErrReviewRequired) || !errors.Is(refusal, firstCause) ||
				!errors.Is(refusal, ErrMismatch) || owner.reviewCause != firstCause ||
				!owner.review || owner.closed || owner.started {
				return errors.Join(firstErr, ErrMismatch, refusal)
			}
		}
		if err := checkUnattempted(); err != nil {
			return errors.Join(firstErr, err)
		}
		if count, err := retainedFixtureFDCount(); err != nil || count != reviewFDs {
			return errors.Join(firstErr, ErrMismatch, err)
		}
	}
	fmt.Println("PHANTOWD_PENDING_OWNER_INPUT_LOSS_READY real_constructor=true never_started=true lost_pin_closed=true close_refused=true review_retained=true unattempted_retained=true repeated_refused=true cause_preserved=true review_fd_count_equal=true unrelated_kept=true client_executed=false scope=qemu-only")
	return nil
}
