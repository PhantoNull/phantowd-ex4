//go:build !linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "errors"

func openSharePolicyReader(directory string) (sharePolicyLoader, func() error, error) {
	if directory == "" {
		return nil, func() error { return nil }, nil
	}
	return nil, nil, errors.New("share configuration storage requires Linux")
}
