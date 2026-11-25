//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io"
)

func openInheritedAccountStore() (*accountStore, error) {
	return nil, errAccountUnavailable
}

func openAccountBackend(string) (accountBackend, error) {
	return nil, errors.New("durable administrator state requires Linux")
}

func provisionInheritedAdministrator(context.Context, io.Reader) error {
	return errors.New("local administrator provisioning requires Linux")
}
