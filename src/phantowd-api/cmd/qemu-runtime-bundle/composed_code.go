//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// Fixed disposable code-view qualification after service inputs are created.
// The native helper supplies a private namespace and drops all authority before
// reaching this function. This is not product construction or a storage grant.
func composedCodeFixture() (result error) {
	defer func() {
		if result != nil {
			fmt.Fprintln(os.Stderr, "PHANTOWD_SAMBA_ROOT_COMPOSED_CODE_FAILED", result)
		}
	}()
	files, aliases, err := inputs()
	if err != nil {
		return err
	}
	plan, err := runtimebundle.NewPlan(files, aliases)
	if err != nil {
		return err
	}
	code := os.NewFile(3, "fixed-code-only-root")
	defer code.Close()
	if _, err := plan.Inspect(context.Background(), code); err != nil {
		return err
	}
	service, err := stageRoot("/run/phantowd-samba-root")
	if err != nil {
		return err
	}
	defer service.Close()
	codeInfo, err := code.Stat()
	if err != nil {
		return err
	}
	serviceInfo, err := service.Stat()
	if err != nil || os.SameFile(codeInfo, serviceInfo) {
		return errors.New("service root is not separate from code-only root")
	}
	for _, file := range files {
		if err := sameComposedCodeObject(code, service, file.Path); err != nil {
			return err
		}
	}
	for _, name := range []string{"etc/passwd", "etc/group", "etc/nsswitch.conf", "etc/hosts", "etc/protocols", "etc/services", "etc/samba/smb.conf"} {
		fd, err := unix.Openat2(int(service.Fd()), name, &unix.OpenHow{
			Flags:   unix.O_PATH | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
		})
		if err != nil {
			return errors.New("fixed composed configuration absent")
		}
		var info unix.Stat_t
		statErr := unix.Fstat(fd, &info)
		closeErr := unix.Close(fd)
		if statErr != nil || closeErr != nil || info.Mode&unix.S_IFMT != unix.S_IFREG || info.Uid != 0 || info.Gid != 0 {
			return errors.New("fixed composed configuration type")
		}
	}
	fmt.Println("PHANTOWD_SAMBA_ROOT_CODE_VIEWS_READY code_only=true config_separate=true same_inodes=true readonly_views=true scope=qemu-only")
	return nil
}

func sameComposedCodeObject(code, service *os.File, name string) error {
	// Deliberately allow crossing only the fixed composed code bind views; this
	// is not the complete code census and does not replace Inspect's NO_XDEV.
	var observations [2]unix.Stat_t
	for i, root := range []*os.File{code, service} {
		resolve := uint64(unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS)
		if i == 0 {
			resolve |= unix.RESOLVE_NO_XDEV
		}
		fd, err := unix.Openat2(int(root.Fd()), name, &unix.OpenHow{
			Flags: unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOFOLLOW, Resolve: resolve,
		})
		if err != nil {
			return errors.New("composed code object unavailable")
		}
		var filesystem unix.Statfs_t
		statErr := unix.Fstat(fd, &observations[i])
		fsErr := unix.Fstatfs(fd, &filesystem)
		closeErr := unix.Close(fd)
		if statErr != nil || fsErr != nil || closeErr != nil || filesystem.Flags&unix.ST_RDONLY == 0 {
			return errors.New("composed code view is not read-only")
		}
	}
	a, b := observations[0], observations[1]
	if a.Dev != b.Dev || a.Ino != b.Ino || a.Mode != b.Mode || a.Size != b.Size ||
		a.Uid != b.Uid || a.Gid != b.Gid || a.Mtim != b.Mtim || a.Ctim != b.Ctim {
		return errors.New("composed code is not the inspected object")
	}
	return nil
}
