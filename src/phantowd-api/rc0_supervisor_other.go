//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io"
)

func runRC0Management(context.Context, string, string, string) error {
	return errors.New("RC0 management supervision requires Linux")
}

func runRC0BootManagement(context.Context) error {
	return errors.New("RC0 boot supervision requires Linux")
}

func provisionInheritedRC0TLS(io.Reader, string, string) error {
	return errors.New("RC0 TLS provisioning requires Linux")
}
