//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
)

// RunAccessFixtureQEMU is a finite synthetic-guest campaign, not product startup.
func (o *SourceRuntimeQEMU) RunAccessFixtureQEMU(ctx context.Context) error {
	if err := o.enter(ctx); err != nil {
		return err
	}
	defer func() { <-o.gate }()
	if o.review {
		return ErrReviewRequired
	}
	if o.closed || o.accessAttempted {
		return ErrState
	}
	s, err := o.roots.enter()
	if err != nil {
		return err
	}
	defer s.leave()
	if err := o.verify(ctx, s); err != nil {
		return err
	}
	if len(s.roots) != 3 {
		return ErrInvalid
	}
	var sources [4]*os.File
	for i, root := range s.roots {
		sources[i] = root.file
	}
	o.accessAttempted = true
	if len(s.pins) != 1 {
		return o.fail(ErrInvalid)
	}
	o.accessVolume, err = s.pins[0].OpenDirectory(".")
	if err != nil {
		return o.fail(err)
	}
	sources[3] = o.accessVolume
	o.access, err = runtimebundle.NewNFSSourceAccessQEMU(ctx, o.lease, sources)
	if err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_ACCESS_FAILURE phase=constructor")
		return o.fail(err)
	}
	if err := o.access.Run(ctx); err != nil {
		fmt.Fprintln(os.Stderr, "PHANTOWD_NFS_SOURCE_ACCESS_FAILURE phase=run")
		return o.fail(err)
	}
	if err := o.access.Close(ctx); err != nil {
		return o.fail(err)
	}
	o.accessSettled = true
	if err := o.accessVolume.Close(); err != nil {
		return o.fail(err)
	}
	o.accessVolume = nil
	return o.verify(ctx, s)
}
