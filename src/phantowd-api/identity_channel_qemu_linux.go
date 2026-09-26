//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityrpc"
)

const identitySocketDir = "/run/phantowd-identity-channel-fixture"
const identitySocket = identitySocketDir + "/channel"

// Fixed disposable-guest listener, NOT product socket provisioning. The
// production HTTP server never opens it. Each invocation owns one step and
// three sequential connections from an actually unprivileged child process.
func exerciseQEMUIdentityChannel(operation identityrpc.Operation, phase string) error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	if phase != "group" && phase != "user" {
		return errors.New("invalid channel fixture phase")
	}
	if err := os.Mkdir(identitySocketDir, 0711); err != nil {
		return err
	}
	defer os.Remove(identitySocketDir) // exact empty directory created above
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: identitySocket, Net: "unix"})
	if err != nil {
		return err
	}
	defer l.Close()
	if err := os.Chown(identitySocket, 0, 65534); err != nil {
		return err
	}
	if err := os.Chmod(identitySocket, 0620); err != nil {
		return err
	}
	server, err := identityrpc.NewOperation(65534, operation)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "/usr/bin/phantowd-api", "--qemu-identity-client="+phase)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
	cmd.Dir = "/"
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}, Setpgid: true}
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		return errors.New("channel fixture child start failed")
	}
	waited := false
	defer func() {
		if !waited {
			cmd.Process.Kill()
			cmd.Wait()
		}
	}()
	for i := 0; i < 3; i++ {
		deadline, _ := ctx.Deadline()
		if err := l.SetDeadline(deadline); err != nil {
			return err
		}
		conn, err := l.AcceptUnix()
		if err != nil {
			return errors.New("channel fixture accept failed")
		}
		if err := server.Serve(ctx, conn); err != nil {
			return err
		}
	}
	err = cmd.Wait()
	waited = true
	if err != nil {
		return errors.New("unprivileged channel fixture failed")
	}
	return nil
}

func runQEMUIdentityClient(phase string) error {
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" || os.Getuid() != 65534 || os.Geteuid() != 65534 {
		return errors.New("wrong channel fixture process")
	}
	if phase != "group" && phase != "user" {
		return errors.New("invalid channel fixture phase")
	}
	want, next := uint64(1), "group-confirmed"
	if phase == "user" {
		want, next = 3, "unix-confirmed"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	requests := []identityrpc.Request{{Version: 1, Action: "status", AccountID: "managed"},
		{Version: 1, Action: "step", AccountID: "managed", Revision: want},
		{Version: 1, Action: "step", AccountID: "managed", Revision: want}}
	for i, req := range requests {
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "unix", identitySocket)
		if err != nil {
			return err
		}
		reply, err := identityrpc.Call(ctx, conn.(*net.UnixConn), req)
		if err != nil {
			return err
		}
		if i == 0 && (reply.Code != "ok" || reply.Revision != want) ||
			i == 1 && (reply.Code != "ok" || reply.Revision != want+2 || reply.Phase != next) ||
			i == 2 && reply.Code != "conflict" {
			return errors.New("channel fixture response mismatch")
		}
	}
	return nil
}
