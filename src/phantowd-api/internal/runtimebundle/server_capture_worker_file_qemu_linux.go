//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

// Fixed proc observation, not duplication of the worker's open-file description.
// The caller has already retained/rechecked the original worker generation.
func captureWorkerFileSlotQEMU(ctx context.Context, proc *os.File, initial unix.Stat_t) (slot string, flags uint32, result error) {
	if ctx == nil || proc == nil || initial.Mode&unix.S_IFMT != unix.S_IFREG {
		return "", 0, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	var fs unix.Statfs_t
	var root unix.Stat_t
	mode, err := unix.FcntlInt(proc.Fd(), unix.F_GETFL, 0)
	if err != nil || mode&unix.O_ACCMODE != unix.O_RDONLY || mode&unix.O_PATH != 0 || unix.Fstat(int(proc.Fd()), &root) != nil || root.Mode&unix.S_IFMT != unix.S_IFDIR || unix.Fstatfs(int(proc.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return "", 0, ErrInvalid
	}
	fd, err := unix.Openat(int(proc.Fd()), "fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", 0, err
	}
	directory := os.NewFile(uintptr(fd), "original-worker-fd-census")
	defer func() {
		if err := directory.Close(); err != nil {
			slot, flags = "", 0
			result = errors.Join(result, err)
		}
	}()
	names, err := directory.Readdirnames(257)
	if err != nil && err != io.EOF || len(names) > 256 {
		return "", 0, ErrMismatch
	}
	if extra, err := directory.Readdirnames(1); len(extra) != 0 || err != io.EOF {
		return "", 0, ErrMismatch
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return "", 0, err
		}
		if !pendingNumberQEMU(name, 31, false) {
			return "", 0, ErrMismatch
		}
		var observed, after unix.Stat_t
		if unix.Fstatat(fd, name, &observed, 0) != nil {
			return "", 0, ErrMismatch
		}
		if observed.Dev != initial.Dev || observed.Ino != initial.Ino {
			continue
		}
		if !samePendingObjectQEMU(initial, observed) {
			return "", 0, ErrMismatch
		}
		infoFD, err := unix.Openat(int(proc.Fd()), "fdinfo/"+name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return "", 0, err
		}
		info := os.NewFile(uintptr(infoFD), "original-worker-fd-flags")
		data, readErr := io.ReadAll(io.LimitReader(info, 4097))
		if err := errors.Join(readErr, info.Close()); err != nil {
			return "", 0, err
		}
		candidate, err := captureWorkerFDFlagsQEMU(data)
		if err != nil || unix.Fstatat(fd, name, &after, 0) != nil || !samePendingObjectQEMU(observed, after) {
			return "", 0, errors.Join(ErrMismatch, err)
		}
		if candidate&unix.O_PATH != 0 {
			continue
		} // Pathref is not a data FD.
		if candidate&unix.O_ACCMODE != unix.O_RDONLY || slot != "" {
			return "", 0, ErrMismatch
		}
		slot, flags = name, candidate
	}
	if slot == "" {
		return "", 0, ErrMismatch
	}
	if err := ctx.Err(); err != nil {
		return "", 0, err
	}
	return slot, flags, nil
}

func captureWorkerFDFlagsQEMU(data []byte) (uint32, error) {
	if len(data) == 0 || len(data) > 4096 {
		return 0, ErrMismatch
	}
	var flags uint64
	found := false
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 || fields[0] != "flags:" {
			continue
		}
		if found || len(fields) != 2 {
			return 0, ErrMismatch
		}
		value, err := strconv.ParseUint(fields[1], 8, 32)
		canonical := strconv.FormatUint(value, 8)
		if value != 0 {
			canonical = "0" + canonical
		}
		// 64-bit userspace defines O_LARGEFILE as zero, while fdinfo reports
		// the kernel's forced asm-generic bit. ARMv5 uses its own x/sys ABI
		// value. Do not admit arbitrary flags to hide the difference.
		largeFile := uint64(unix.O_LARGEFILE)
		if largeFile == 0 && (runtime.GOARCH == "amd64" || runtime.GOARCH == "arm64") {
			largeFile = 0o100000
		}
		allowed := uint64(unix.O_ACCMODE|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_PATH) | largeFile
		if err != nil || fields[1] != canonical || value & ^allowed != 0 {
			return 0, ErrMismatch
		}
		flags, found = value, true
	}
	if !found {
		return 0, ErrMismatch
	}
	return uint32(flags), nil
}
