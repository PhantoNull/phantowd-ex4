//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

type Owner struct{}

func (*Plan) NewOwner(context.Context, *os.File, []processowner.MemberSpec) (*Owner, error) {
	return nil, ErrUnavailable
}
func (*Owner) Start(context.Context) (OwnerSnapshot, error)   { return OwnerSnapshot{}, ErrUnavailable }
func (*Owner) Observe(context.Context) (OwnerSnapshot, error) { return OwnerSnapshot{}, ErrUnavailable }
func (*Owner) Close(context.Context) error                    { return ErrUnavailable }
func (*Owner) Supervise(context.Context, time.Duration) (OwnerSnapshot, error) {
	return OwnerSnapshot{}, ErrUnavailable
}
