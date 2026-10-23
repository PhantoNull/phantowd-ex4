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
	bound         fileserviceplan.Freshness
	retained      bool
	running       bool
	starts, stops int
	releases      int
	fail          string
	cause         error
	hook          func(string)
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
func (b *preparedBackend) VerifyStopped(context.Context) error {
	if b.running {
		return ErrState
	}
	return b.result("stopped")
}
func (b *preparedBackend) Start(context.Context) error {
	b.running = true
	b.starts++
	return b.result("start")
}
func (b *preparedBackend) VerifyReady(context.Context) error {
	if !b.running {
		return ErrState
	}
	return b.result("ready")
}
func (b *preparedBackend) Stop(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	b.stops++
	if err := b.result("stop"); err != nil {
		return err
	}
	b.running = false
	return nil
}

// ExerciseRunningQEMU models lifecycle effects in memory, never kernel exports.
func ExerciseRunningQEMU(candidate fileserviceplan.NFSv3Candidate, expected fileserviceplan.Freshness) error {
	for _, fail := range []string{"", "ready"} {
		backend := &preparedBackend{bound: expected, retained: true, fail: fail}
		owner, err := NewQEMU(candidate, backend)
		if err != nil {
			return err
		}
		err = owner.Start(context.Background())
		if fail != "" {
			if !errors.Is(err, ErrReviewRequired) || backend.running || !backend.retained || backend.stops != 1 || owner.Close(context.Background()) != ErrReviewRequired {
				return ErrInvalid
			}
			continue
		}
		if err != nil || !backend.running || owner.Close(context.Background()) != nil || backend.running || backend.retained || backend.stops != 1 || backend.releases != 1 {
			return ErrInvalid
		}
	}
	return nil
}
func (b *preparedBackend) Release(context.Context) error {
	if b.running {
		return ErrState
	}
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
