//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import "github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"

// Immutable fixture for pre-authenticated policy-handler probes, never the
// listening API's account backend. The synthetic verifier is not an enrollment
// password. No write, setup, reset or fallback behavior is available.
type qemuStaticAccount struct{}

func (qemuStaticAccount) Load() (admincredentials.Document, error) {
	return admincredentials.Document{Version: admincredentials.Version, Revision: 1,
		Admin: admincredentials.Account{Username: "fixture-admin", PasswordHash: "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"}}, nil
}
func (qemuStaticAccount) Initialize(string, string) error { return errAccountConfigured }
func (qemuStaticAccount) Close() error                    { return nil }
