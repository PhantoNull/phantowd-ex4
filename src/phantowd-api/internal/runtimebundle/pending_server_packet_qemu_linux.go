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

// Private transport prerequisite only: neither a producer/worker lease nor
// service authority. The future containing Owner must retain qualified code,
// bind actual worker credentials/lifetime and settle its producer before close.
type pendingServerPacketQEMU struct {
	self                             *pendingServerPacketQEMU
	gate                             chan struct{}
	receiver, sender                 *os.File
	originalReceiver, originalSender *os.File
	left, right                      pendingServerPacketEndpointQEMU
	sequence                         uint32
	initial                          pendingServerPacketObservationQEMU
	review, closed, closeTried       bool
	releaseTried                     bool
	releaseErr                       error
}

type pendingServerPacketEndpointQEMU struct {
	fd                    int
	device, inode, cookie uint64
	mode, uid, gid        uint32
	peer                  unix.Ucred
	passsecUnavailable    bool
}

type pendingServerPacketObservationQEMU struct {
	metadata    pendingServerOpenMetadataQEMU
	credentials unix.Ucred
}

func newPendingServerPacketQEMU(ctx context.Context) (*pendingServerPacketQEMU, error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	pair := &pendingServerPacketQEMU{
		gate:     make(chan struct{}, 1),
		receiver: os.NewFile(uintptr(fds[0]), "original-server-frame-receiver"),
		sender:   os.NewFile(uintptr(fds[1]), "original-server-frame-sender"),
	}
	pair.self = pair
	pair.originalReceiver, pair.originalSender = pair.receiver, pair.sender
	err = unix.SetsockoptInt(fds[0], unix.SOL_SOCKET, unix.SO_PASSCRED, 1)
	if err == nil {
		pair.left, err = pendingServerPacketEndpointSnapshotQEMU(pair.receiver, 1, true)
	}
	if err == nil {
		pair.right, err = pendingServerPacketEndpointSnapshotQEMU(pair.sender, 0, true)
	}
	creator := unix.Ucred{Pid: int32(os.Getpid()), Uid: uint32(os.Geteuid()), Gid: uint32(os.Getegid())}
	if err == nil && (pair.left.cookie == pair.right.cookie || pair.left.peer != creator || pair.right.peer != creator) {
		err = ErrMismatch
	}
	if err == nil {
		err = ctx.Err()
	}
	if err != nil {
		// Constructor has never exported an endpoint or started a producer.
		pair.closeTried = true
		closeErr := pair.releaseEndpointsQEMU()
		if closeErr != nil {
			pair.review = true
			return pair, errors.Join(ErrReviewRequired, err, closeErr)
		}
		return nil, err
	}
	return pair, nil
}

func pendingServerPacketEndpointSnapshotQEMU(file *os.File, passcred int, strict bool) (pendingServerPacketEndpointQEMU, error) {
	if file == nil {
		return pendingServerPacketEndpointQEMU{}, ErrInvalid
	}
	fd := int(file.Fd())
	var stat unix.Stat_t
	if fd < 0 || unix.Fstat(fd, &stat) != nil || stat.Mode&unix.S_IFMT != unix.S_IFSOCK {
		return pendingServerPacketEndpointQEMU{}, ErrMismatch
	}
	for _, option := range []struct{ name, value int }{{unix.SO_DOMAIN, unix.AF_UNIX}, {unix.SO_TYPE, unix.SOCK_SEQPACKET}, {unix.SO_PROTOCOL, 0}} {
		got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option.name)
		if err != nil || got != option.value {
			return pendingServerPacketEndpointQEMU{}, ErrMismatch
		}
	}
	// Linux returns EOPNOTSUPP for this Unix option when SECURITY_NETWORK is
	// compiled out: scm_passec is then empty, not an unknown ancillary source.
	// Retain that availability state; every other error or enabled value refuses.
	passsec, passsecErr := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_PASSSEC)
	passsecUnavailable := errors.Is(passsecErr, unix.EOPNOTSUPP)
	if (passsecErr != nil && !passsecUnavailable) || (strict && !passsecUnavailable && passsec != 0) {
		return pendingServerPacketEndpointQEMU{}, ErrMismatch
	}
	if strict {
		for _, option := range []struct{ name, value int }{{unix.SO_PASSCRED, passcred}, {unix.SO_PASSPIDFD, 0}} {
			got, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, option.name)
			if err != nil || got != option.value {
				return pendingServerPacketEndpointQEMU{}, ErrMismatch
			}
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0)
		if err != nil || flags != unix.FD_CLOEXEC {
			return pendingServerPacketEndpointQEMU{}, ErrMismatch
		}
		flags, err = unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || flags != unix.O_RDWR {
			return pendingServerPacketEndpointQEMU{}, ErrMismatch
		}
	}
	cookie, err := unix.GetsockoptUint64(fd, unix.SOL_SOCKET, unix.SO_COOKIE)
	peer, peerErr := unix.GetsockoptUcred(fd, unix.SOL_SOCKET, unix.SO_PEERCRED)
	if err != nil || peerErr != nil || cookie == 0 || peer == nil {
		return pendingServerPacketEndpointQEMU{}, ErrMismatch
	}
	return pendingServerPacketEndpointQEMU{fd: fd, device: uint64(stat.Dev), inode: uint64(stat.Ino), cookie: cookie, mode: stat.Mode, uid: stat.Uid, gid: stat.Gid, peer: *peer, passsecUnavailable: passsecUnavailable}, nil
}

func (p *pendingServerPacketQEMU) endpoints(strict bool) error {
	if p.receiver != p.originalReceiver || p.sender != p.originalSender {
		return ErrMismatch
	}
	left, err := pendingServerPacketEndpointSnapshotQEMU(p.receiver, 1, strict)
	right, rightErr := pendingServerPacketEndpointSnapshotQEMU(p.sender, 0, strict)
	if err != nil || rightErr != nil || left != p.left || right != p.right {
		return ErrMismatch
	}
	return nil
}

func (p *pendingServerPacketQEMU) enter(ctx context.Context) error {
	if ctx == nil || p == nil || p.self != p || p.gate == nil {
		return ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case p.gate <- struct{}{}:
		return nil
	default:
		return processowner.ErrBusy
	}
}

func (p *pendingServerPacketQEMU) fail() (pendingServerPacketObservationQEMU, error) {
	p.review = true
	return pendingServerPacketObservationQEMU{}, ErrReviewRequired
}

func (p *pendingServerPacketQEMU) queueEmpty() bool {
	var data [1]byte
	// No control buffer: Linux discards ancillary rights without installing
	// descriptors. Even an empty packet/EOF refuses; only EAGAIN means empty.
	_, _, err := unix.Recvfrom(int(p.receiver.Fd()), data[:], unix.MSG_PEEK|unix.MSG_DONTWAIT)
	return errors.Is(err, unix.EAGAIN)
}

func (p *pendingServerPacketQEMU) next(ctx context.Context) (pendingServerPacketObservationQEMU, error) {
	if err := p.enter(ctx); err != nil {
		return pendingServerPacketObservationQEMU{}, err
	}
	defer func() { <-p.gate }()
	if p.closed || p.closeTried || p.review || p.sequence >= 2 {
		return p.fail()
	}
	if p.endpoints(true) != nil {
		return p.fail()
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	var data [89]byte
	// Exactly one credential record: no room for SCM_RIGHTS after Linux delivers
	// credentials. Extra ancillary data truncates/refuses, not imported authority.
	control := make([]byte, unix.CmsgSpace(unix.SizeofUcred))
	for {
		if err := ctx.Err(); err != nil {
			_, review := p.fail()
			return pendingServerPacketObservationQEMU{}, errors.Join(review, err)
		}
		n, ancillary, flags, _, err := unix.Recvmsg(int(p.receiver.Fd()), data[:], control,
			unix.MSG_DONTWAIT|unix.MSG_CMSG_CLOEXEC)
		if errors.Is(err, unix.EAGAIN) {
			select {
			case <-ctx.Done():
				_, review := p.fail()
				return pendingServerPacketObservationQEMU{}, errors.Join(review, ctx.Err())
			case <-time.After(2 * time.Millisecond):
				continue
			}
		}
		if err != nil || n != 88 || flags & ^(unix.MSG_EOR|unix.MSG_CMSG_CLOEXEC) != 0 {
			return p.fail()
		}
		messages, err := unix.ParseSocketControlMessage(control[:ancillary])
		if err != nil || len(messages) != 1 || messages[0].Header.Level != unix.SOL_SOCKET ||
			messages[0].Header.Type != unix.SCM_CREDENTIALS || len(messages[0].Data) != unix.SizeofUcred {
			return p.fail()
		}
		credentials, err := unix.ParseUnixCredentials(&messages[0])
		metadata, decodeErr := decodePendingServerOpenFrameQEMU(data[:n], p.sequence+1)
		if err != nil || decodeErr != nil || credentials.Pid <= 1 || metadata.workerPID != uint32(credentials.Pid) {
			return p.fail()
		}
		got := pendingServerPacketObservationQEMU{metadata: metadata, credentials: *credentials}
		if (p.sequence == 1 && (got != p.initial || !p.queueEmpty())) ||
			p.endpoints(true) != nil || ctx.Err() != nil {
			return p.fail()
		}
		if p.sequence == 0 {
			p.initial = got
		}
		p.sequence++
		return got, nil
	}
}

func (p *pendingServerPacketQEMU) recheck(ctx context.Context) error {
	if err := p.enter(ctx); err != nil {
		return err
	}
	defer func() { <-p.gate }()
	if p.closed || p.closeTried || p.review || p.sequence != 2 ||
		p.endpoints(true) != nil || !p.queueEmpty() || p.endpoints(true) != nil || ctx.Err() != nil {
		_, err := p.fail()
		return err
	}
	return nil
}

func (p *pendingServerPacketQEMU) close() error {
	if err := p.enter(context.Background()); err != nil {
		return err
	}
	defer func() { <-p.gate }()
	if p.closed {
		return nil
	}
	if p.closeTried || p.endpoints(false) != nil {
		p.review = true
		return ErrReviewRequired
	}
	p.closeTried = true
	if p.releaseEndpointsQEMU() != nil {
		p.review = true
		return ErrReviewRequired
	}
	p.closed = true
	return nil
}

// Private release boundary only. The constructor owns unpublished endpoints;
// later callers own the gate and must independently settle every producer.
// Preserve the first terminal result before any later access to endpoint fields.
// An uncertain earlier close must not attempt the remaining endpoint or retry.
func (p *pendingServerPacketQEMU) releaseEndpointsQEMU() error {
	if p.releaseTried {
		return p.releaseErr
	}
	p.releaseTried = true
	p.releaseErr = p.receiver.Close()
	if p.releaseErr == nil {
		p.releaseErr = p.sender.Close()
	}
	return p.releaseErr
}
