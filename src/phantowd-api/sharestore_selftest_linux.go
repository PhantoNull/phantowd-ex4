//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/sharestore"
)

func exerciseQEMUShareStore() error {
	dir, err := os.MkdirTemp("", "phantowd-share-store-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	s, err := sharestore.Open(dir)
	if err != nil {
		return err
	}
	defer s.Close()
	if _, err := s.Load(); !errors.Is(err, sharestore.ErrNotInitialized) {
		return errors.New("share store did not distinguish missing configuration")
	}
	config := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
	if err := s.Commit(0, config); err != nil {
		return err
	}
	if other, err := sharestore.Open(dir); !errors.Is(err, sharestore.ErrBusy) {
		if other != nil {
			other.Close()
		}
		return errors.New("share store did not enforce writer exclusion")
	}
	config.Revision = 2
	if err := s.Commit(1, config); err != nil {
		return err
	}
	if err := s.Commit(1, config); !errors.Is(err, sharestore.ErrConflict) {
		return errors.New("share store accepted a stale revision")
	}
	if err := s.Close(); err != nil {
		return err
	}
	reopened, err := sharestore.Open(dir)
	if err != nil {
		return err
	}
	defer reopened.Close()
	loaded, err := reopened.Load()
	if err != nil || loaded.Revision != 2 {
		return errors.New("share store did not preserve revision across reopen")
	}
	return nil
}
