//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"net/http"
)

func openNASPolicyHTTP(_ *authController, path string, _, _ bool) (http.Handler, func() error, error) {
	if path == "" {
		return nil, func() error { return nil }, nil
	}
	return nil, nil, errors.New("NAS policy channel unavailable")
}
