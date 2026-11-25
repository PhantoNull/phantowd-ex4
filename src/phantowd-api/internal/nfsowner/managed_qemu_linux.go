// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build qemu

package nfsowner

import (
	"context"
	"errors"
)

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
	case Running:
		if !errors.Is(m.rpc.Close(ctx), ErrState) || !errors.Is(m.exports.Close(ctx), ErrState) {
			return errors.New("running NFS released managed helper or export references")
		}
	default:
		return ErrState
	}
	return nil
}
