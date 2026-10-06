//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/stateunmountdiag"
	"golang.org/x/sys/unix"
)

type qemuStateProcReader struct{}

func (qemuStateProcReader) ProcessIDs() ([]int, bool, error) {
	directory, err := os.Open("/proc")
	if err != nil {
		return nil, false, err
	}
	defer directory.Close()
	return stateunmountdiag.ReadProcessIDs(directory)
}

func (qemuStateProcReader) ProcessStatus(pid int) (string, int, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "status"))
	if err != nil {
		return "", 0, procError(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 4096)
	name := ""
	parentPID := -1
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "Name:") {
			name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		} else if strings.HasPrefix(line, "PPid:") {
			parentPID, err = strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "PPid:")))
		}
		if name != "" && parentPID >= 0 {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return "", 0, err
	}
	if name == "" || parentPID < 0 {
		return "", 0, errors.New("process status lacks bounded identity fields")
	}
	return name, parentPID, nil
}

func (qemuStateProcReader) FDNumbers(pid int) ([]int, bool, error) {
	directory := filepath.Join("/proc", strconv.Itoa(pid), "fd")
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, false, procError(err)
	}
	fds := make([]int, 0, len(entries))
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err == nil && fd >= 0 {
			fds = append(fds, fd)
		}
	}
	sort.Ints(fds)
	truncated := len(fds) > stateunmountdiag.MaxFDsPerProcess
	if truncated {
		fds = fds[:stateunmountdiag.MaxFDsPerProcess]
	}
	return fds, truncated, nil
}

func (qemuStateProcReader) Link(pid int, object string) (string, error) {
	if object != "cwd" && object != "root" {
		if !strings.HasPrefix(object, "fd/") {
			return "", unix.EINVAL
		}
		if fd, err := strconv.Atoi(strings.TrimPrefix(object, "fd/")); err != nil || fd < 0 {
			return "", unix.EINVAL
		}
	}
	target, err := os.Readlink(filepath.Join("/proc", strconv.Itoa(pid), object))
	if err != nil {
		return "", procError(err)
	}
	return target, nil
}

func (qemuStateProcReader) MountInfo(pid int) ([]string, bool, error) {
	file, err := os.Open(filepath.Join("/proc", strconv.Itoa(pid), "mountinfo"))
	if err != nil {
		return nil, false, procError(err)
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024), 4096)
	lines := make([]string, 0, stateunmountdiag.MaxMountInfoLines)
	truncated := false
	for scanner.Scan() {
		if len(lines) == stateunmountdiag.MaxMountInfoLines {
			truncated = true
			break
		}
		lines = append(lines, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return lines, truncated, err
	}
	return lines, truncated, nil
}

func procError(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return stateunmountdiag.ErrNoSuchProcess
	}
	return err
}

func qemuStateUnmountDiagnostic(err error, ownerPID int) string {
	errno := "E_OTHER"
	switch {
	case errors.Is(err, unix.EBUSY):
		errno = "EBUSY"
	case errors.Is(err, unix.EIO):
		errno = "EIO"
	case errors.Is(err, unix.EINVAL):
		errno = "EINVAL"
	case errors.Is(err, unix.ENOTEMPTY):
		errno = "ENOTEMPTY"
	}
	return stateunmountdiag.Capture(errno, ownerPID, qemuStateAnchor, "/dev/sdb", qemuStateProcReader{})
}

func emitQEMUStateUnmountDiagnostic(err error) {
	fmt.Println(qemuStateUnmountDiagnostic(err, os.Getpid()))
}
