//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"errors"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"
)

// VerifyQEMUSymlinkRefusal proves the fixed opener rejects a symlink that
// points to a valid fixture block device with the expected generation. This
// test-only entry point is excluded from non-QEMU firmware builds.
func VerifyQEMUSymlinkRefusal(device ObservedBlockDevice) error {
	if validateObservedBlockDevices([]ObservedBlockDevice{device}) != nil {
		return ErrUnsafe
	}
	root, err := os.MkdirTemp("/run", "phantowd-dev-link-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	if err := os.Symlink("/dev/"+device.Name, filepath.Join(root, device.Name)); err != nil {
		return err
	}
	directoryFD, err := unix.Openat2(unix.AT_FDCWD, root, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	defer unix.Close(directoryFD)
	sources, err := openObservedBlockSourcesAt(directoryFD, []ObservedBlockDevice{device})
	if err == nil {
		for _, source := range sources {
			source.File.Close()
		}
		return errors.New("source symlink unexpectedly opened")
	}
	if !errors.Is(err, ErrUnsafe) || sources != nil {
		return errors.New("symlink refusal returned an invalid result")
	}
	return nil
}
