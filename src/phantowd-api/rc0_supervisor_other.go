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

func runRC0BootManagement(context.Context, *rc0BootStopAuthority, func() error) error {
	return errors.New("RC0 boot supervision requires Linux")
}

type rc0BootStopAuthority struct{}

func manageRC0BootService(context.Context, string) error {
	return errors.New("RC0 boot service requires Linux")
}

func provisionInheritedRC0TLS(io.Reader, string, string) error {
	return errors.New("RC0 TLS provisioning requires Linux")
}

func provisionInheritedRC0ServiceIdentities(context.Context, io.Reader) error {
	return errors.New("RC0 service identity provisioning requires Linux")
}
