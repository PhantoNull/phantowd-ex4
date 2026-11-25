// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"io"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func extractRC0PolicyConfirmation(input io.Reader, output io.Writer, expected string) error {
	revision, err := strconv.ParseUint(expected, 10, 64)
	if err != nil || strconv.FormatUint(revision, 10) != expected || revision < 2 {
		return naspolicy.ErrInvalid
	}
	backup, err := io.ReadAll(io.LimitReader(input, naspolicy.MaxBackupBytes+1))
	if err != nil {
		return err
	}
	policy, err := naspolicy.SavedConfirmation(backup, revision)
	if err != nil {
		return err
	}
	_, err = output.Write(policy)
	return err
}
