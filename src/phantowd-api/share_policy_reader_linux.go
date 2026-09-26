// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/sharestore"
)

// An explicit private pre-provisioned directory only. Open validates/syncs
// current state and holds the exclusive store lock; GET only calls Load.
// No automatic initialization, directory creation, cleanup or pending recovery.
func openSharePolicyReader(directory string) (sharePolicyLoader, func() error, error) {
	if directory == "" {
		return nil, func() error { return nil }, nil
	}
	store, err := sharestore.Open(directory)
	if err != nil {
		return nil, nil, errors.New("share configuration storage unavailable")
	}
	return func() (*shareconfig.Config, error) {
		config, err := store.Load()
		if errors.Is(err, sharestore.ErrNotInitialized) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &config, nil
	}, store.Close, nil
}
