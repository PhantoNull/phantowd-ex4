//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import "context"

func Collect(context.Context) (*Observation, error) { return nil, ErrUnavailable }
