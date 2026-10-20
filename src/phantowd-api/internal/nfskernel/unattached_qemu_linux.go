//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package nfskernel

import (
	"context"
	"errors"

	"golang.org/x/sys/unix"
)

// Set only after THIS controller's real bind returns EADDRINUSE, before any
// listener attachment/thread write. A selector or missing component is not proof.
type unattachedSocketQEMU struct {
	bindCause, closeCause       error
	attempted, closed, verified bool
}

func checkUnattachedSocketQEMU(fd int, original nfsSocketIdentityQEMU) error {
	if !matchesNFSSocketIdentityQEMU(fd, original) {
		return ErrRefused
	}
	address, err := unix.Getsockname(fd)
	ipv4, ok := address.(*unix.SockaddrInet4)
	accepting, acceptingErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_ACCEPTCONN)
	if err != nil || !ok || ipv4.Port != 0 || ipv4.Addr != [4]byte{} || acceptingErr != nil || accepting != 0 ||
		!matchesNFSSocketIdentityQEMU(fd, original) {
		return ErrRefused
	}
	return nil
}

func (k *ControllerQEMU) originalReviewedReservationQEMU() bool {
	kernelRetention.Lock()
	defer kernelRetention.Unlock()
	return kernelRetention.active == k && len(kernelRetention.objects) == 1 && kernelRetention.objects[0] == k
}

// The original controller gate and OS thread are held. The only mutation is
// one close of its original unbound socket. No NFSD write, foreign socket stop,
// namespace/control release, retry or review reset is admitted.
func (k *ControllerQEMU) stopUnattachedSocketQEMU(ctx context.Context) error {
	u := k.unattached
	if u == nil || !errors.Is(u.bindCause, unix.EADDRINUSE) || !k.review || k.started || k.stopped ||
		k.socket < 0 || k.uncertain != nil || u.attempted || u.closed || u.verified || u.closeCause != nil {
		return k.retain()
	}
	u.attempted, k.stopped = true, true // BEFORE observation/close; uncertainty cannot retry.
	k.phase = "unattached-guard"
	if !k.originalReviewedReservationQEMU() || k.profile(ctx, false) != nil ||
		checkUnattachedSocketQEMU(k.socket, k.socketIdentity) != nil || k.check(ctx) != nil {
		return errors.Join(k.retain(), u.bindCause)
	}
	k.phase = "unattached-socket-close"
	fd := k.socket
	k.socket = -1 // Never use/close this descriptor number again, even after EIO/EINTR.
	u.closeCause = unix.Close(fd)
	if u.closeCause != nil {
		return errors.Join(k.retain(), u.bindCause, u.closeCause)
	}
	u.closed = true
	k.phase = "unattached-stopped-profile"
	if k.profile(ctx, false) != nil || !k.originalReviewedReservationQEMU() || ctx.Err() != nil {
		return errors.Join(k.retain(), u.bindCause)
	}
	u.verified = true
	return errors.Join(k.retain(), u.bindCause) // Verified absence is still reviewed failure.
}

// Fresh read-only witness of this ORIGINAL reviewed, unstarted controller AFTER
// its one verified socket close. This is not healthy admission, release, global
// domain ownership or complete export/client quiescence.
func (k *ControllerQEMU) CheckUnattachedStoppedQEMU(ctx context.Context) error {
	if err := k.enter(ctx, true); err != nil {
		return err
	}
	defer k.leave()
	u := k.unattached
	if u == nil || !errors.Is(u.bindCause, unix.EADDRINUSE) || !u.attempted || !u.closed || !u.verified || u.closeCause != nil ||
		!k.review || k.started || !k.stopped || k.socket >= 0 || k.uncertain != nil || !k.originalReviewedReservationQEMU() {
		return ErrRefused
	}
	k.phase = "check-unattached-stopped"
	if k.profile(ctx, false) != nil {
		return k.retain()
	}
	return ctx.Err()
}
