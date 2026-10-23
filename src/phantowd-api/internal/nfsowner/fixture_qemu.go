//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"errors"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
)

// The shared backend models memory-only inputs, not server/kernel authority.
type preparedBackend struct {
	bound    fileserviceplan.Freshness
	retained bool
	releases int
	fail     string
	cause    error
	hook     func(string)
}

func (b *preparedBackend) result(name string) error {
	if b.hook != nil {
		b.hook(name)
	}
	if b.fail == name {
		return errors.Join(errors.New("backend details"), b.cause)
	}
	return nil
}

func (b *preparedBackend) CheckInputs(_ context.Context, c fileserviceplan.NFSv3Candidate) error {
	if !b.retained || !c.FreshAgainst(b.bound) {
		return context.Canceled
	}
	return b.result("inputs")
}
func (b *preparedBackend) VerifyStopped(context.Context) error { return b.result("stopped") }
func (b *preparedBackend) Release(context.Context) error {
	b.releases++
	if err := b.result("release"); err != nil {
		return err
	}
	b.retained = false
	return nil
}

// ExercisePreparedQEMU checks the same prepared-only closure on the guest CPU.
func ExercisePreparedQEMU(candidate fileserviceplan.NFSv3Candidate, expected fileserviceplan.Freshness) error {
	backend := &preparedBackend{bound: expected, retained: true}
	owner, err := NewQEMU(candidate, backend)
	if err != nil {
		return err
	}
	if owner.Close(context.Background()) != nil || owner.Close(context.Background()) != nil ||
		backend.retained || backend.releases != 1 {
		return ErrInvalid
	}
	state, err := owner.Observe()
	if err != nil || state != Closed {
		return ErrInvalid
	}
	return nil
}
