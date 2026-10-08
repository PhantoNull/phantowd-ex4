//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"encoding/json"
	"errors"
)

// NativeSessionPairQEMU is a private nonserializable witness from one exact
// backend and complete real inventory. It grants no activation or HTTP input.
type NativeSessionPairQEMU struct {
	backend      *NativeBackendQEMU
	target, peer smbStatusSession
}

func (NativeSessionPairQEMU) MarshalJSON() ([]byte, error) {
	return nil, errors.New("native session witness is not serializable")
}

func (*NativeSessionPairQEMU) UnmarshalJSON([]byte) error {
	return errors.New("native session witness cannot be deserialized")
}

func nativeSessionsQEMU(output []byte) (map[string]smbStatusSession, error) {
	if _, err := parseSMBStatusHasUser(output, "qpmanaged"); err != nil {
		return nil, ErrUnavailable // validates EVERY record and qualified generation
	}
	var inventory struct {
		Sessions map[string]smbStatusSession `json:"sessions"`
	}
	if json.Unmarshal(output, &inventory) != nil {
		return nil, ErrUnavailable
	}
	return inventory.Sessions, nil
}

func (b *NativeBackendQEMU) readNativeSessionsQEMU(ctx context.Context) (map[string]smbStatusSession, error) {
	if b == nil || ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed || b.inner == nil {
		return nil, ErrInvalid
	}
	b.inner.mu.RLock()
	defer b.inner.mu.RUnlock()
	if b.inner.closed || b.inner.config == nil || b.inner.runner == nil {
		return nil, ErrInvalid
	}
	// This native-only observation includes complete admission on both sides
	// of the worker; the generic command adapter's two-second limit is unchanged.
	statusCtx, cancel := context.WithTimeout(ctx, 2*sessionStatusTimeout)
	defer cancel()
	output, err := b.inner.runner.Run(statusCtx, smbstatusPath,
		[]string{"-j", "-s", configArgument}, b.inner.config, nil, true)
	defer clear(output)
	if err != nil || statusCtx.Err() != nil {
		return nil, errors.Join(ErrUnavailable, statusCtx.Err())
	}
	return nativeSessionsQEMU(output)
}

func (b *NativeBackendQEMU) ObserveNativeSessionPairQEMU(ctx context.Context) (NativeSessionPairQEMU, error) {
	sessions, err := b.readNativeSessionsQEMU(ctx)
	if err != nil || len(sessions) != 2 {
		return NativeSessionPairQEMU{}, ErrUnavailable
	}
	pair := NativeSessionPairQEMU{backend: b}
	for _, session := range sessions {
		switch session.Username {
		case "qpmanaged":
			if pair.target.SessionID != "" {
				return NativeSessionPairQEMU{}, ErrUnavailable
			}
			pair.target = session
		case "qpsecond":
			if pair.peer.SessionID != "" {
				return NativeSessionPairQEMU{}, ErrUnavailable
			}
			pair.peer = session
		default:
			return NativeSessionPairQEMU{}, ErrUnavailable
		}
	}
	if pair.target.SessionID == "" || pair.peer.SessionID == "" || pair.target.ServerID == pair.peer.ServerID {
		return NativeSessionPairQEMU{}, ErrUnavailable
	}
	return pair, nil
}

func (b *NativeBackendQEMU) VerifyNativePeerSessionQEMU(ctx context.Context, before NativeSessionPairQEMU) error {
	if b == nil || before.backend != b || before.target.SessionID == "" || before.peer.SessionID == "" {
		return ErrInvalid
	}
	sessions, err := b.readNativeSessionsQEMU(ctx)
	if err != nil || len(sessions) != 1 {
		return ErrUnavailable
	}
	peer, ok := sessions[before.peer.SessionID]
	if !ok || peer != before.peer {
		return ErrUnavailable // fresh login, changed generation or target row is not continuity
	}
	return nil
}
