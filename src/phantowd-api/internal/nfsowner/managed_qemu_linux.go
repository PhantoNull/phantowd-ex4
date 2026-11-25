// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build qemu

package nfsowner

import (
	"context"
	"errors"
	"net"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

// NewManagedLinuxQEMU admits the existing disconnected QEMU fixtures before
// their image includes nftables. Production always uses NewManagedLinux.
func NewManagedLinuxQEMU(ctx context.Context, inputs *RetainedInputs, grants LinuxServiceGrants) (*Owner, error) {
	if !nfskernel.SmokeFixtureQEMU() && !nfskernel.PeerServerQEMU() {
		return nil, ErrInvalid
	}
	return newManagedLinux(ctx, inputs, grants, true)
}

// CheckManagedRefusalsQEMU probes the real components without exposing them.
func CheckManagedRefusalsQEMU(ctx context.Context, owner *Owner) error {
	if err := owner.acquire(ctx); err != nil {
		return err
	}
	defer func() { <-owner.gate }()
	backend, ok := owner.backend.(*retainedRuntime)
	if !ok {
		return ErrInvalid
	}
	m, ok := backend.Runtime.(*managedLinux)
	if !ok {
		return ErrInvalid
	}
	switch owner.state {
	case Prepared:
		if !errors.Is(m.rpc.StartMountd(ctx), ErrState) {
			return errors.New("managed mountd accepted startup before rpcbind")
		}
		if err := verifyOccupiedMountPortQEMU(ctx, m.rpc); err != nil {
			return err
		}
		if err := verifyForeignRPCBindQEMU(ctx, m.rpc); err != nil {
			return err
		}
	case Running:
		if !errors.Is(m.rpc.Close(ctx), ErrState) || !errors.Is(m.exports.Close(ctx), ErrState) {
			return errors.New("running NFS released managed helper or export references")
		}
	default:
		return ErrState
	}
	return nil
}

func verifyForeignRPCBindQEMU(ctx context.Context, rpc *RPC) error {
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: rpcLocalPath, Net: "unix"})
	if err != nil {
		return err
	}
	refused := rpc.VerifyStopped(ctx)
	if err := listener.Close(); err != nil {
		return err
	}
	if !errors.Is(refused, ErrState) {
		return errors.Join(errors.New("managed RPC admitted a foreign local socket"), refused)
	}
	return rpc.VerifyStopped(ctx)
}

func verifyOccupiedMountPortQEMU(ctx context.Context, rpc *RPC) error {
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(mountdPort))
	var config net.ListenConfig
	packet, err := config.ListenPacket(ctx, "udp4", address)
	if err != nil {
		return err
	}
	refused := rpc.VerifyStopped(ctx)
	if err := packet.Close(); err != nil {
		return err
	}
	if !errors.Is(refused, ErrState) {
		return errors.Join(errors.New("managed mountd admitted an occupied UDP port"), refused)
	}
	return rpc.VerifyStopped(ctx)
}
