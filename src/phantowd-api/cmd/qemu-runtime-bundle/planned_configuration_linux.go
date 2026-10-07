//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

const plannedConfigurationPathQEMU = "/run/phantowd-planned-samba-configuration"

// Owns only one fixed disposable configuration mount, never a service lease.
// Caller may remove it only after the native runtime's verified normal Close.
type plannedConfigurationStageQEMU struct{ identity unix.Statx_t }

func stagePlannedConfigurationQEMU(ctx context.Context, runtime *runtimebundle.NativeSambaRuntimeQEMU, candidate fileserviceplan.SambaRoleCandidate) (_ *plannedConfigurationStageQEMU, result error) {
	if ctx == nil || runtime == nil {
		return nil, errors.New("planned configuration stage requires context/runtime")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	commandLine, commandErr := os.ReadFile("/proc/cmdline")
	var runFS, etcFS unix.Statfs_t
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 ||
		commandErr != nil || !strings.Contains(" "+string(commandLine)+" ", " phantowd_samba_ext4_fixture=1 ") ||
		unix.Statfs("/run", &runFS) != nil || runFS.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &etcFS) != nil || etcFS.Type != unix.TMPFS_MAGIC {
		return nil, errors.New("planned configuration stage fixture guard")
	}
	_, documents, err := runtimebundle.SambaRoleDocumentsQEMU(candidate)
	if err != nil {
		return nil, err
	}
	if err := os.Mkdir(plannedConfigurationPathQEMU, 0755); err != nil {
		return nil, err
	}
	if err := os.Mkdir(plannedConfigurationPathQEMU+"/samba", 0755); err != nil {
		return nil, err
	}
	for name, contents := range documents {
		mode := os.FileMode(0644)
		if name == "samba/smb.conf" {
			mode = 0600
		}
		file, err := os.OpenFile(plannedConfigurationPathQEMU+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return nil, err
		}
		_, writeErr := file.WriteString(contents)
		if err := errors.Join(writeErr, file.Close()); err != nil {
			return nil, err
		}
	}
	// Controlled writable-mount metadata alias, never given to the runtime or
	// any child. A malformed staged mode must fail before the role is published.
	writer, err := os.Open(plannedConfigurationPathQEMU + "/samba/smb.conf")
	if err != nil {
		return nil, err
	}
	defer func() {
		if writer != nil {
			result = errors.Join(result, writer.Close())
		}
	}()
	if err := unix.Mount(plannedConfigurationPathQEMU, plannedConfigurationPathQEMU, "", unix.MS_BIND, ""); err != nil {
		return nil, err
	}
	if err := unix.Mount("", plannedConfigurationPathQEMU, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
		return nil, err
	}
	stage := &plannedConfigurationStageQEMU{}
	if err := unix.Statx(unix.AT_FDCWD, plannedConfigurationPathQEMU, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &stage.identity); err != nil || stage.identity.Mask&unix.STATX_MNT_ID_UNIQUE == 0 {
		return nil, errors.New("planned configuration mount identity unavailable")
	}
	fd, err := unix.Open(plannedConfigurationPathQEMU, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	caller := os.NewFile(uintptr(fd), "planned-configuration-caller")
	if err := runtime.RetainPlannedConfigurationQEMU(ctx, caller, fileserviceplan.SambaRoleCandidate{}); !errors.Is(err, runtimebundle.ErrInvalid) {
		return nil, errors.Join(errors.New("empty planned configuration candidate admitted"), caller.Close())
	}
	if err := writer.Chmod(0400); err != nil {
		return nil, errors.Join(err, caller.Close())
	}
	if err := runtime.RetainPlannedConfigurationQEMU(ctx, caller, candidate); !errors.Is(err, runtimebundle.ErrMismatch) {
		return nil, errors.Join(errors.New("malformed staged configuration mode admitted"), caller.Close())
	}
	if err := writer.Chmod(0600); err != nil {
		return nil, errors.Join(err, caller.Close())
	}
	closeErr := writer.Close()
	writer = nil
	if closeErr != nil {
		return nil, errors.Join(closeErr, caller.Close())
	}
	err = runtime.RetainPlannedConfigurationQEMU(ctx, caller, candidate)
	err = errors.Join(err, caller.Close())
	if err != nil {
		return nil, err // Quarantine is retained for guest disposal on late failure.
	}
	if !errors.Is(runtime.RetainPlannedConfigurationQEMU(ctx, nil, candidate), runtimebundle.ErrReviewRequired) ||
		!errors.Is(runtime.CheckNativeStartupQEMU(ctx), runtimebundle.ErrReviewRequired) ||
		!errors.Is(runtime.StartNativeDaemonQEMU(ctx), runtimebundle.ErrReviewRequired) {
		return nil, errors.New("inert configuration role replaced or admitted a daemon")
	}
	return stage, nil
}

func (s *plannedConfigurationStageQEMU) removeAfterRuntimeClose() error {
	if s == nil {
		return errors.New("planned configuration stage absent")
	}
	var current unix.Statx_t
	var fs unix.Statfs_t
	const flags = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC
	if unix.Statx(unix.AT_FDCWD, plannedConfigurationPathQEMU, unix.AT_SYMLINK_NOFOLLOW, unix.STATX_BASIC_STATS|unix.STATX_MNT_ID_UNIQUE, &current) != nil ||
		current.Mask&unix.STATX_MNT_ID_UNIQUE == 0 || current.Mnt_id != s.identity.Mnt_id || current.Ino != s.identity.Ino ||
		current.Dev_major != s.identity.Dev_major || current.Dev_minor != s.identity.Dev_minor || current.Uid != 0 || current.Gid != 0 ||
		unix.Statfs(plannedConfigurationPathQEMU, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&flags != flags {
		return errors.New("planned configuration teardown identity drift")
	}
	if err := unix.Unmount(plannedConfigurationPathQEMU, 0); err != nil {
		return err // Never lazy-unmount or retry uncertain cleanup.
	}
	for _, name := range []string{"passwd", "group", "nsswitch.conf", "hosts", "protocols", "services", "samba/smb.conf", "samba", ""} {
		if err := os.Remove(plannedConfigurationPathQEMU + "/" + name); err != nil {
			return err
		}
	}
	return nil
}
