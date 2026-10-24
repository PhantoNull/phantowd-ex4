//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// Fixed QEMU/root dispatch only. No NFS program, RPC or kernel service is started.
func nfsCodeFixture(expectedHex string) error {
	decoded, err := hex.DecodeString(expectedHex)
	if err != nil || len(decoded) != 32 {
		return runtimebundle.ErrInvalid
	}
	var expected [32]byte
	copy(expected[:], decoded)
	file, err := os.Open("/usr/lib/phantowd/qemu-nfs-inputs.json")
	if err != nil {
		return err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, (128<<10)+1))
	if closeErr := file.Close(); readErr != nil || closeErr != nil || len(data) > 128<<10 {
		return runtimebundle.ErrInvalid
	}
	plan, err := runtimebundle.DecodeNFSExpectedQEMU(data, expected)
	if err != nil {
		return err
	}
	source, err := stageRoot("/")
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := stageRoot("/run/phantowd-nfs-code")
	if err != nil {
		return err
	}
	defer destination.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := plan.StageQEMU(ctx, source, destination); err != nil {
		return errors.Join(errors.New("NFS code staging"), err)
	}
	if err := unix.Mount("", "/run/phantowd-nfs-code", "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NODEV|unix.MS_NOSUID, ""); err != nil {
		return err
	}
	got, err := runtimebundle.ProbeNFSCodeQEMU(ctx, data, expected, destination)
	if err != nil {
		return errors.Join(errors.New("NFS retained input capture"), err)
	}
	fmt.Printf("PHANTOWD_NFS_CODE_INPUTS_READY files=%d aliases=%d bytes=%d separate_root=true readonly=true duplicate_caller_closed=true released=true fd_equal=true execution=false kernel_backend=false scope=qemu-only\n", got.Files, got.Aliases, got.Bytes)
	return nil
}
