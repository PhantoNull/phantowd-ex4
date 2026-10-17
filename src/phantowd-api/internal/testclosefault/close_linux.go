//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package testclosefault is used only by terminal test subprocesses. It is not
// a product injection/configuration boundary or a complete syscall sandbox.
package testclosefault

import (
	"bytes"
	"errors"
	"os"
	"runtime"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Executable selects only existing fixture code, never a caller-selected tool.
// Guest BusyBox is setuid and correctly forbidden by executable admission; use
// the existing root-owned0755 probe staged by the guarded static-owner driver.
func Executable() (string, error) {
	if runtime.GOARCH != "arm" {
		return "/bin/sh", nil
	}
	model, modelErr := os.ReadFile("/sys/firmware/devicetree/base/model")
	commandLine, commandErr := os.ReadFile("/proc/cmdline")
	if modelErr != nil || commandErr != nil || string(model) != "ARM Versatile PB\x00" ||
		len(commandLine) > 4096 || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 {
		return "", errors.New("unqualified constructor fixture")
	}
	for _, field := range bytes.Fields(commandLine) {
		if string(field) == "phantowd_code_owner_fixture=1" {
			return "/usr/sbin/phantowd-runtime-bundle-probe", nil
		}
	}
	return "", errors.New("constructor fixture flag absent")
}

// Install permanently locks the calling goroutine to its OS thread and denies
// close of exactly fd with EIO, WITHOUT closing it. The subprocess must terminate
// after testing; never return this filtered thread to an application thread pool.
// There are no file/device/network opens, raw descriptor closes or child starts.
func Install(fd int) error {
	if fd < 0 {
		return errors.New("invalid close-fault descriptor")
	}
	var arch uint32
	switch runtime.GOARCH {
	case "amd64":
		arch = unix.AUDIT_ARCH_X86_64
	case "arm":
		arch = unix.AUDIT_ARCH_ARM
	case "arm64":
		arch = unix.AUDIT_ARCH_AARCH64
	default:
		return errors.New("unqualified close-fault architecture")
	}
	runtime.LockOSThread()
	filter := []unix.SockFilter{
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: arch, Jt: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(unix.SYS_CLOSE), Jf: 3},
		{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 16},
		{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: uint32(fd), Jf: 1},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EIO)},
		{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW},
	}
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	var pinned runtime.Pinner
	pinned.Pin(&program)
	pinned.Pin(&filter[0])
	defer pinned.Unpin()
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	return unix.Prctl(unix.PR_SET_SECCOMP, unix.SECCOMP_MODE_FILTER, uintptr(unsafe.Pointer(&program)), 0, 0)
}
