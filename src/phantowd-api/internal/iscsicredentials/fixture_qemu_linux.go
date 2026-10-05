//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package iscsicredentials

import (
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

// OpenQEMUFixture provisions only a NEW generated disposable directory, with
// fixed public synthetic data. It is excluded from product binaries. This is
// not an import/generation/rotation API and never accepts caller secret bytes.
func OpenQEMUFixture(directory string) (*Owner, error) {
	return openSyntheticFixture(directory, []entry{{Ref: "fixture-secret", Secret: "PublicSyntheticToken1!"}})
}

// Fixed public protocol tokens for the existing loopback libiscsi fixture only.
// This provisioner is absent from product binaries and accepts no secret input.
func OpenQEMULIOFixture(directory string) (*Owner, error) {
	return openSyntheticFixture(directory, []entry{{Ref: "fixture-secret", Secret: "synthetic-chap-only-2026"},
		{Ref: "fixture-outbound", Secret: "synthetic-outbound-only-2026"}})
}

func openSyntheticFixture(directory string, entries []entry) (*Owner, error) {
	if os.Geteuid() != 0 {
		return nil, ErrUnavailable
	}
	if os.Mkdir(directory, 0700) != nil {
		return nil, ErrUnavailable
	}
	s, err := revisionstore.OpenWithCodec(directory, codec())
	if err != nil {
		return nil, ErrUnavailable
	}
	d := document{Kind: "phantowd-chap-credentials", SchemaVersion: 1, Revision: 1,
		Entries: entries}
	commitErr := s.Commit(0, d)
	if errors.Join(commitErr, s.Close()) != nil {
		return nil, ErrUnavailable
	}
	return Open(directory)
}
