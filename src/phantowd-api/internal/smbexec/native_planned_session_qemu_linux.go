//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
)

// NativePlannedSessionQEMU is a private point-in-time witness, not a retained
// data handle or activation authority. The fixed planned service grants only
// qpsecond; accepting the two-account fixture would weaken that policy.
type NativePlannedSessionQEMU struct {
	backend *NativeBackendQEMU
	session smbStatusSession
}

var ErrNativePlannedSessionChangedQEMU = errors.New("native original planned session changed")

func (NativePlannedSessionQEMU) MarshalJSON() ([]byte, error) {
	return nil, errors.New("native planned session witness is not serializable")
}

func (*NativePlannedSessionQEMU) UnmarshalJSON([]byte) error {
	return errors.New("native planned session witness cannot be deserialized")
}

func (b *NativeBackendQEMU) ObservePlannedSessionQEMU(ctx context.Context) (NativePlannedSessionQEMU, error) {
	sessions, err := b.readNativeSessionsQEMU(ctx)
	if err != nil {
		return NativePlannedSessionQEMU{}, err
	}
	if len(sessions) != 1 {
		return NativePlannedSessionQEMU{}, ErrUnavailable
	}
	for _, session := range sessions {
		if session.Username != "qpsecond" {
			return NativePlannedSessionQEMU{}, ErrUnavailable
		}
		return NativePlannedSessionQEMU{backend: b, session: session}, nil
	}
	return NativePlannedSessionQEMU{}, ErrUnavailable
}

func (b *NativeBackendQEMU) VerifyPlannedSessionQEMU(ctx context.Context, before NativePlannedSessionQEMU) error {
	if b == nil || before.backend != b || before.session.SessionID == "" || before.session.Username != "qpsecond" {
		return ErrInvalid
	}
	sessions, err := b.readNativeSessionsQEMU(ctx)
	if err != nil {
		return err
	}
	if len(sessions) != 1 {
		return ErrNativePlannedSessionChangedQEMU
	}
	session, present := sessions[before.session.SessionID]
	if !present || session != before.session {
		return ErrNativePlannedSessionChangedQEMU
	}
	return nil
}
