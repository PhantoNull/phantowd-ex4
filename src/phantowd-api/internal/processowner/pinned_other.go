//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"os"
)

type PinnedSet struct{}

func NewPinnedSet([]MemberSpec, []*os.File) (*PinnedSet, error) { return nil, ErrUnavailable }
func (*PinnedSet) Start(context.Context) (SetSnapshot, error)   { return SetSnapshot{}, ErrUnavailable }
func (*PinnedSet) Observe(context.Context) (SetSnapshot, error) { return SetSnapshot{}, ErrUnavailable }
func (*PinnedSet) Stop(context.Context) (SetSnapshot, error)    { return SetSnapshot{}, ErrUnavailable }
func (*PinnedSet) Close() error                                 { return ErrUnavailable }
