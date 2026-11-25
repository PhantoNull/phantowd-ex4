//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
)

func runRC0Management(context.Context, string, string, string) error {
	return errors.New("RC0 management supervision requires Linux")
}
