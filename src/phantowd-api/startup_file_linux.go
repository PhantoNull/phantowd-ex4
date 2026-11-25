// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

var errStartupFile = errors.New("startup file unavailable or unsafe")

func takeStartupFile(descriptor int, kind uint32) (*os.File, error) {
	flags, err := unix.FcntlInt(uintptr(descriptor), unix.F_GETFD, 0)
	var info unix.Stat_t
	if err != nil || flags&unix.FD_CLOEXEC != 0 || unix.Fstat(descriptor, &info) != nil || info.Mode&unix.S_IFMT != kind {
		return nil, errStartupFile
	}
	if _, err := unix.FcntlInt(uintptr(descriptor), unix.F_SETFD, flags|unix.FD_CLOEXEC); err != nil {
		return nil, errStartupFile
	}
	return os.NewFile(uintptr(descriptor), "inherited-startup-file"), nil
}

func readPrivateStartupFile(file *os.File, owner uint32, limit int64) ([]byte, unix.Stat_t, error) {
	if file == nil {
		return nil, unix.Stat_t{}, errStartupFile
	}
	flags, err := unix.FcntlInt(file.Fd(), unix.F_GETFL, 0)
	var before, after unix.Stat_t
	if err != nil || flags&(unix.O_ACCMODE|unix.O_PATH) != unix.O_RDONLY ||
		unix.Fstat(int(file.Fd()), &before) != nil || !privateStartupFileSafe(before, owner, limit) {
		return nil, unix.Stat_t{}, errStartupFile
	}
	data := make([]byte, before.Size)
	if _, err := file.ReadAt(data, 0); err != nil || unix.Fstat(int(file.Fd()), &after) != nil {
		clear(data)
		return nil, unix.Stat_t{}, errStartupFile
	}
	after.Atim = before.Atim
	if after != before {
		clear(data)
		return nil, unix.Stat_t{}, errStartupFile
	}
	return data, before, nil
}

func privateStartupFileSafe(st unix.Stat_t, owner uint32, limit int64) bool {
	return st.Uid == owner && st.Nlink == 1 && (st.Mode == unix.S_IFREG|0400 || st.Mode == unix.S_IFREG|0600) &&
		st.Size > 0 && st.Size <= limit
}
