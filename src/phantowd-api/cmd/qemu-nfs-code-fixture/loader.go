//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

// Only the existing static launcher can supply this fixture's constrained
// environment/root/identity. No argument selects a program or loader option.
func observeLoader() error {
	if runtime.GOARCH != "arm" || os.Getuid() != 1000 || os.Geteuid() != 1000 || os.Getgid() != 1000 || os.Getegid() != 1000 {
		return errors.New("loader fixture identity")
	}
	var caps [2]unix.CapUserData
	header := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if unix.Capget(&header, &caps[0]) != nil || err != nil || nnp != 1 {
		return errors.New("loader fixture privilege")
	}
	for _, cap := range caps {
		if cap.Effective != 0 || cap.Permitted != 0 || cap.Inheritable != 0 {
			return errors.New("loader fixture capabilities")
		}
	}
	for cap := 0; cap <= unix.CAP_LAST_CAP; cap++ {
		bound, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(cap), 0, 0, 0)
		ambient, aerr := unix.PrctlRetInt(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_IS_SET, uintptr(cap), 0, 0)
		if err != nil || aerr != nil || bound != 0 || ambient != 0 {
			return errors.New("loader fixture capability sets")
		}
	}
	groups, err := os.Getgroups()
	if err != nil || len(groups) != 0 || len(os.Environ()) != 2 || os.Getenv("LC_ALL") != "C" || os.Getenv("PATH") != "/usr/bin:/bin" {
		return errors.New("loader fixture environment")
	}
	if cwd, err := os.Getwd(); err != nil || cwd != "/" {
		return errors.New("loader fixture cwd")
	}
	var fs unix.Statfs_t
	const flags = unix.ST_RDONLY | unix.ST_NOSUID | unix.ST_NODEV
	if unix.Statfs("/", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&flags != flags {
		return errors.New("loader fixture root")
	}
	for _, path := range []string{"/proc", "/dev", "/etc", "/run", "/mnt"} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			return errors.New("loader fixture root escaped")
		}
	}
	stopped, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM)
	defer stop()
	for _, entry := range []string{"usr/sbin/rpcbind", "usr/sbin/rpc.mountd", "usr/sbin/exportfs"} {
		fmt.Println("PHANTOWD_NFS_LOADER_BEGIN entry=" + entry)
		ctx, cancel := context.WithTimeout(stopped, 5*time.Second)
		command := exec.CommandContext(ctx, "/lib/ld-linux.so.3", "--inhibit-cache", "--list", "/"+entry)
		command.Env = []string{"LC_ALL=C"}
		command.Stdin, command.Stdout, command.Stderr = os.Stdin, os.Stdout, os.Stdout
		command.WaitDelay = time.Second
		err := command.Run()
		cancel()
		if err != nil {
			return errors.New("loader fixture command")
		}
		fmt.Println("PHANTOWD_NFS_LOADER_END entry=" + entry)
	}
	fmt.Println("PHANTOWD_NFS_LOADER_CHILD_READY")
	<-stopped.Done()
	return nil
}
