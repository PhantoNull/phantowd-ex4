//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservicestore"
)

// Explicit development-only adapter. No implicit path, mkdir, initialization,
// migration or restart/recovery after uncertainty. Production builds refuse it.
func openDevelopmentServiceState(directory string) (*serviceStateBackend, func() error, error) {
	if directory == "" {
		return nil, func() error { return nil }, nil
	}
	s, err := fileservicestore.Open(directory)
	if err != nil {
		return nil, nil, errors.New("service configuration storage unavailable")
	}
	translate := func(err error) error {
		if errors.Is(err, fileservicestore.ErrConflict) {
			return errServiceStateConflict
		}
		if errors.Is(err, fileservicestore.ErrUncertain) {
			return errServiceStateUncertain
		}
		return err
	}
	return &serviceStateBackend{
		load: func() (*fileservice.Config, error) {
			c, err := s.Load()
			if errors.Is(err, fileservicestore.ErrNotInitialized) {
				return nil, nil
			}
			if err != nil {
				return nil, translate(err)
			}
			return &c, nil
		},
		commit: func(expected uint64, c fileservice.Config) error { return translate(s.Commit(expected, c)) },
	}, s.Close, nil
}
