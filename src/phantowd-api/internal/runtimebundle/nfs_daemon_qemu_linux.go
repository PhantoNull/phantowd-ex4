//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Private original-instance lifetime, called only under the original code gate.
// Code/bootstrap/channels are BORROWED; only the PinnedSet belongs to this
// object. Its caller must settle dependent NFSD/clients before stop/close.
// Splitting the old probe stack does not establish product/domain authority.
type nfsDaemonQEMU struct {
	original                                                                       *nfsDaemonQEMU
	code                                                                           *nfsCodeLifetimeQEMU
	child                                                                          *processowner.PinnedSet
	program                                                                        *os.File
	channels                                                                       *NFSMountdChannelsQEMU
	source                                                                         *NFSSourceAccessQEMU
	mountd                                                                         bool
	pid                                                                            int
	inode                                                                          string
	attempted, readyEvidence, stopAttempted, stopped, stoppedProof, closed, review bool
	cause                                                                          error
}

func newNFSDaemonQEMU(ctx context.Context, s *nfsCodeLifetimeQEMU, bootstrap *os.File, channels *NFSMountdChannelsQEMU, mountd bool) (*nfsDaemonQEMU, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if s == nil || bootstrap == nil || s.code == nil || s.configuration == nil || s.configuration.contents == nil || s.state == nil ||
		mountd && channels == nil || !mountd && channels != nil || nfsCodeGuardQEMU() != nil {
		return nil, ErrInvalid
	}
	if err := s.revalidate(ctx); err != nil {
		return nil, err
	}
	d := &nfsDaemonQEMU{code: s, channels: channels, source: s.sourceAccess, mountd: mountd}
	d.original = d
	entry, name, role := "usr/sbin/rpcbind", "nfs-rpcbind", "rpcbind-v1"
	if mountd {
		entry, name, role = "usr/sbin/rpc.mountd", "nfs-mountd", "mountd-v1"
	}
	if mountd && d.source != nil {
		name, role = "nfs-source-mountd", "mountd-source-v1"
	}
	d.program = s.code.files[entry]
	for _, alias := range s.code.plan.aliases {
		if alias.Path == entry {
			d.program = s.code.files[alias.Target]
		}
	}
	if d.program == nil {
		return nil, ErrMismatch
	}
	spec := processowner.MemberSpec{Name: name, Process: processowner.Spec{
		Executable: "/usr/sbin/phantowd-nfs-table-bootstrap", Args: []string{role}, RunAs: &processowner.Credentials{UID: 0, GID: 0},
		Ready:        func(ctx context.Context) (bool, error) { return nfsRPCNullQEMU(ctx, mountd) },
		ReadyTimeout: 5 * time.Second, ProbeInterval: 20 * time.Millisecond, StopTimeout: time.Second,
	}}
	refs := [4]*os.File{s.code.root, s.configuration.contents.root, s.state.root, d.program}
	var err error
	if !mountd {
		d.child, err = processowner.NewNFSRPCBindPinnedQEMU(spec, bootstrap, refs)
	} else if d.source == nil {
		d.child, err = processowner.NewNFSMountdPinnedQEMU(spec, bootstrap, refs, [4]*os.File{channels.files[0], channels.files[1], channels.files[2], channels.namespaces[0]})
	} else {
		a := d.source
		d.child, err = processowner.NewNFSSourceMountdPinnedQEMU(spec, bootstrap, refs, [4]*os.File{channels.files[0], channels.files[1], channels.files[2], channels.namespaces[0]}, [6]*os.File{a.data[0], a.data[1], a.data[2], a.filehandle, a.features, a.volume})
	}
	if err != nil {
		d.review, d.cause = true, err
		return d, err
	}
	return d, nil
}

func (d *nfsDaemonQEMU) valid() bool {
	return d != nil && d.original == d && d.code != nil && d.child != nil && d.program != nil
}

func (d *nfsDaemonQEMU) fail(err error) error {
	d.review = true
	if d.cause == nil {
		d.cause = err
	}
	return err
}

func (d *nfsDaemonQEMU) start(ctx context.Context) error {
	if !d.valid() || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.attempted || d.closed || d.review {
		return ErrUnavailable
	}
	if d.code.sourceAccess != d.source || d.code.revalidate(ctx) != nil {
		return d.fail(ErrMismatch)
	}
	if d.mountd && d.channels.Check(ctx) != nil {
		return d.fail(ErrMismatch)
	}
	d.attempted = true
	started, err := d.child.Start(ctx)
	if len(started.Members) == 1 {
		d.pid = started.Members[0].Process.PID
	}
	if err != nil {
		return d.fail(err)
	}
	d.readyEvidence = started.State == processowner.StateReady && started.Generation == 1 && len(started.Members) == 1 && d.pid > 0 && !started.Members[0].Process.DiagnosticsTruncated
	return nil // Full readiness observation is a separate, explicit operation.
}

func (d *nfsDaemonQEMU) check(ctx context.Context) (result error) {
	if !d.valid() || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if d.review {
		return ErrReviewRequired
	}
	if !d.attempted || d.stopAttempted || d.closed {
		return ErrUnavailable
	}
	if !d.readyEvidence {
		return d.fail(ErrReviewRequired)
	}
	defer func() {
		if result != nil {
			d.fail(result)
		}
	}()
	s := d.code
	if s.sourceAccess != d.source || s.revalidate(ctx) != nil {
		return ErrMismatch
	}
	if err := d.handoff(ctx, false); err != nil {
		return err
	}
	inode, err := nfsRPCListenerQEMU(d.mountd)
	if err != nil || inode == "" || d.inode != "" && d.inode != inode {
		return errors.Join(ErrMismatch, err)
	}
	if err := nfsRPCProcessQEMU(d.pid, s, d.program, inode, d.mountd); err != nil {
		return err
	}
	if d.mountd {
		if observeNFSMountdChannelsQEMU(d.pid, d.channels) != nil || d.channels.Check(ctx) != nil {
			return ErrMismatch
		}
		if d.source != nil && d.source.checkView(d.pid) != nil {
			return ErrMismatch
		}
	}
	if ok, err := nfsRPCNullQEMU(ctx, d.mountd); err != nil || !ok {
		return errors.Join(ErrMismatch, err)
	}
	if again, err := nfsRPCListenerQEMU(d.mountd); err != nil || again != inode {
		return errors.Join(ErrMismatch, err)
	}
	observed, err := d.child.Observe(ctx)
	if err != nil || observed.State != processowner.StateReady || observed.Generation != 1 || len(observed.Members) != 1 || observed.Members[0].Process.PID != d.pid || observed.Members[0].Process.DiagnosticsTruncated {
		return errors.Join(ErrMismatch, err)
	}
	if err := s.revalidate(ctx); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	d.inode = inode
	return nil
}

func (d *nfsDaemonQEMU) handoff(ctx context.Context, stopped bool) error {
	if d.code.sourceAccess != d.source {
		return ErrMismatch
	}
	if d.mountd {
		return nfsMountdHandoffForInputsQEMU(ctx, d.code, d.child, stopped)
	}
	return d.child.CheckNFSRPCBindHandoffQEMU(ctx)
}

// One stop attempt, including after a failed readiness check. Review survives;
// uncertain stop never permits another attempt or release. Caller supplies its
// independent cleanup budget, unchanged from the original nested probes.
func (d *nfsDaemonQEMU) stop(ctx context.Context) error {
	if !d.valid() || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !d.attempted || d.stopAttempted || d.closed {
		return ErrUnavailable
	}
	d.stopAttempted = true
	stopped, err := d.child.Stop(ctx)
	if err != nil || stopped.State != processowner.StateStopped || stopped.Generation != 1 || len(stopped.Members) != 1 ||
		stopped.Members[0].Process.PID != 0 || stopped.Members[0].Process.DiagnosticsTruncated || d.pid <= 0 || !errors.Is(unix.Kill(-d.pid, 0), unix.ESRCH) {
		return d.fail(errors.Join(ErrReviewRequired, err))
	}
	d.stopped = true
	return nil
}

func (d *nfsDaemonQEMU) checkStopped(ctx context.Context) error {
	if !d.valid() || ctx == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !d.stopped || d.closed {
		return ErrUnavailable
	}
	if inode, err := nfsRPCListenerQEMU(d.mountd); err != nil || inode != "" {
		return d.fail(errors.Join(ErrMismatch, err))
	}
	if err := d.handoff(ctx, true); err != nil {
		return d.fail(err)
	}
	if err := ctx.Err(); err != nil {
		return d.fail(err)
	}
	d.stoppedProof = true
	return nil
}

func (d *nfsDaemonQEMU) close() error {
	if !d.valid() {
		return ErrInvalid
	}
	if d.review {
		return ErrReviewRequired
	}
	if d.closed {
		return nil
	}
	if d.attempted && (!d.stopped || !d.stoppedProof) {
		return ErrUnavailable
	}
	if err := d.child.Close(); err != nil {
		return d.fail(err)
	}
	d.closed = true
	return nil
}
