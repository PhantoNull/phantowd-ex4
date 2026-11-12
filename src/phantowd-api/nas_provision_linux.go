//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"io"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

func provisionInheritedNASPolicy(installation string) error {
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("NAS policy provisioning requires root")
	}
	flags, err := unix.FcntlInt(3, unix.F_GETFD, 0)
	var fs unix.Statfs_t
	if err != nil || flags&unix.FD_CLOEXEC != 0 || unix.Fstatfs(3, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC {
		return errors.New("inherited local ext filesystem directory required")
	}
	parent := os.NewFile(3, "nas-policy-provisioning-parent")
	confirmed, err := io.ReadAll(io.LimitReader(os.Stdin, naspolicy.MaxInputBytes+1))
	if err != nil {
		parent.Close()
		return errors.New("initial NAS policy input unavailable")
	}
	provisionErr := naspolicystore.ProvisionInitial(parent, installation, confirmed)
	if parent.Close() != nil {
		return errors.New("NAS policy provisioning outcome requires review")
	}
	if errors.Is(provisionErr, naspolicystore.ErrReview) {
		return errors.New("NAS policy provisioning outcome requires review")
	}
	if provisionErr != nil {
		return errors.New("NAS policy provisioning refused")
	}
	return nil
}
