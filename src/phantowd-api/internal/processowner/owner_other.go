//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import "context"

type managedProcess struct{}

type diagnosticRing struct{}

func (*diagnosticRing) snapshot() []byte    { return nil }
func (*diagnosticRing) status() (int, bool) { return 0, false }

func (o *Owner) Start(context.Context, Spec) (Snapshot, error) {
	return Snapshot{}, ErrUnavailable
}

func (o *Owner) Stop(context.Context) (Snapshot, error) {
	return Snapshot{}, ErrUnavailable
}

func (o *Owner) Observe(context.Context) (Snapshot, error) {
	return Snapshot{}, ErrUnavailable
}
