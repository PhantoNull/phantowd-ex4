//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import "context"

type Set struct{}

func NewSet([]MemberSpec) (*Set, error) { return nil, ErrUnavailable }

func (*Set) Start(context.Context) (SetSnapshot, error) {
	return SetSnapshot{}, ErrUnavailable
}

func (*Set) Observe(context.Context) (SetSnapshot, error) {
	return SetSnapshot{}, ErrUnavailable
}

func (*Set) Stop(context.Context) (SetSnapshot, error) {
	return SetSnapshot{}, ErrUnavailable
}
