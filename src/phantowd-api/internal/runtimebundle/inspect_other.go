//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"os"
)

func (*Plan) Inspect(context.Context, *os.File) (Observation, error) {
	return Observation{}, ErrUnavailable
}
