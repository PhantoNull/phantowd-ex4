// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build qemu

package nfsowner

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

// InstallManagedStateConfigQEMU supplies the shipped configuration to the
// disposable guest after stock NFS shutdown. The returned cleanup is for
// verified teardown only.
func InstallManagedStateConfigQEMU(ctx context.Context) (func() error, error) {
	if !nfskernel.SmokeFixtureQEMU() && !nfskernel.PeerServerQEMU() {
		return nil, ErrInvalid
	}
	file, err := os.OpenFile(nfsConfigPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	_, writeErr := file.WriteString(managedNFSConfig)
	original, statErr := file.Stat()
	if err := errors.Join(writeErr, statErr, file.Close()); err != nil {
		return nil, err
	}
	if err := verifyNFSConfig(ctx); err != nil {
		return nil, err
	}
	return func() error {
		current, err := os.Lstat(nfsConfigPath)
		if err != nil || !os.SameFile(original, current) {
			return ErrState
		}
		return os.Remove(nfsConfigPath)
	}, nil
}

func CheckStaleManagedStateQEMU(ctx context.Context, inputs *RetainedInputs, grants LinuxServiceGrants) error {
	if !nfskernel.SmokeFixtureQEMU() {
		return ErrInvalid
	}
	if err := os.Mkdir(nfsStatePath, 0700); err != nil {
		return err
	}
	const payload = "previous lifetime"
	sentinel := filepath.Join(nfsStatePath, "sentinel")
	if err := os.WriteFile(sentinel, []byte(payload), 0600); err != nil {
		return err
	}
	owner, err := NewManagedLinux(ctx, inputs, grants)
	if owner != nil || !errors.Is(err, ErrState) || constructionreview.Contains(err) {
		return errors.Join(errors.New("managed NFS did not cleanly refuse stale state"), err)
	}
	data, err := os.ReadFile(sentinel)
	if err != nil || string(data) != payload {
		return errors.New("stale NFS state was changed")
	}
	if err := os.Remove(sentinel); err != nil {
		return err
	}
	return os.Remove(nfsStatePath)
}

func CheckManagedTablesQEMU(ctx context.Context, exportPath, client string) error {
	if !nfskernel.SmokeFixtureQEMU() && !nfskernel.PeerServerQEMU() {
		return ErrInvalid
	}
	if err := verifyNFSConfig(ctx); err != nil {
		return err
	}
	for _, table := range []struct{ name, entry string }{
		{"etab", exportPath + "\t"},
		{"rmtab", client + ":" + exportPath + ":"},
	} {
		data, err := os.ReadFile(filepath.Join(nfsStatePath, table.name))
		if err != nil || !strings.Contains(string(data), table.entry) {
			return errors.Join(errors.New("managed "+table.name+" does not contain the fixture export"), err)
		}
	}
	return nil
}

func CheckManagedStateReapedQEMU() error {
	if _, err := os.Lstat(nfsStatePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("managed NFS state remained after closure")
	}
	return nil
}
