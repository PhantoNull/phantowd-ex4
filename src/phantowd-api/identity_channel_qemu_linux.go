//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityrpc"
)

const identitySocketDir = "/run/phantowd-identity-channel-fixture"
const identitySocket = identitySocketDir + "/channel"

// Fixed disposable-guest directory with the reusable protected listener. The
// production HTTP server never opens it. An actually unprivileged child drives
// a fixed phase or the two-account routing scenario through one protected socket.
func exerciseQEMUIdentityChannel(owner *identityowner.Owner, phase string) error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	if phase != "group" && phase != "user" && phase != "second" && phase != "smb-create" && phase != "smb-password" && phase != "smb-enable" && phase != "smb-disable" && phase != "smb-reenable" {
		return errors.New("invalid channel fixture phase")
	}
	if err := os.Mkdir(identitySocketDir, 0710); err != nil {
		return err
	}
	defer os.Remove(identitySocketDir) // exact empty directory created above
	if err := os.Chown(identitySocketDir, 0, 65534); err != nil {
		return err
	}
	server, err := identityrpc.NewRouterWithSMB(65534,
		func(id string) identityrpc.Operation { return owner.Operation(id) },
		func(id string) identityrpc.SMBOperation { return owner.SMB(id) })
	if err != nil {
		return err
	}
	l, err := identityrpc.Listen(identitySocketDir, 65534, server)
	if err != nil {
		return err
	}
	defer l.Close()
	if other, err := identityrpc.Listen(identitySocketDir, 65534, server); err != identityrpc.ErrBusy || other != nil {
		if other != nil {
			other.Close()
		}
		return errors.New("channel fixture listener lease missing")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
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
	err = cmd.Wait()
	waited = true
	if err != nil {
		return errors.New("unprivileged channel fixture failed")
	}
	if err := l.Close(); err != nil {
		return err
	}
	if err := <-done; err != nil {
		return err
	}
	if _, err := os.Lstat(identitySocket); !errors.Is(err, os.ErrNotExist) {
		return errors.New("channel fixture socket retained after drain")
	}
	fmt.Printf("PHANTOWD_IDENTITY_LISTENER_READY phase=%s protected=true lease_exclusive=true drained=true scope=isolated-qemu-only\n", phase)
	return nil
}

func runQEMUIdentityClient(phase string) error {
	clientUID, clientGID, ownerServiceClient, principalErr := qemuIdentityOwnerClientPrincipal(phase)
	if principalErr != nil {
		return principalErr
	}
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" {
		return errors.New("wrong channel fixture process")
	}
	if ownerServiceClient {
		if os.Getuid() != int(clientUID) || os.Geteuid() != int(clientUID) || os.Getgid() != int(clientGID) {
			return errors.New("wrong boot owner fixture peer")
		}
		return runQEMUIdentityOwnerClient(phase)
	}
	if os.Getuid() != 65534 || os.Geteuid() != 65534 {
		return errors.New("wrong channel fixture process")
	}
	if phase != "group" && phase != "user" && phase != "second" && phase != "smb-create" && phase != "smb-password" && phase != "smb-enable" && phase != "smb-disable" && phase != "smb-reenable" {
		return errors.New("invalid channel fixture phase")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	if phase == "smb-create" || phase == "smb-password" || phase == "smb-enable" || phase == "smb-disable" || phase == "smb-reenable" {
		requests := []struct {
			request identityrpc.SMBRequest
			phase   string
			rev     uint64
		}{
			{identityrpc.SMBRequest{Action: "begin", AccountID: "second", Revision: 5}, "reserved", 1},
			{identityrpc.SMBRequest{Action: "step", AccountID: "second", Revision: 1}, "disabled-no-password", 3},
			{identityrpc.SMBRequest{Action: "status", AccountID: "second"}, "disabled-no-password", 3},
		}
		if phase == "smb-password" {
			secret := []byte("public-qemu-owner-enrollment")
			defer clear(secret)
			requests = []struct {
				request identityrpc.SMBRequest
				phase   string
				rev     uint64
			}{
				{identityrpc.SMBRequest{Action: "set-password-disabled", AccountID: "second", Revision: 3, Password: secret}, "credential-set-disabled", 5},
				{identityrpc.SMBRequest{Action: "status", AccountID: "second"}, "credential-set-disabled", 5},
				{identityrpc.SMBRequest{Action: "set-password-disabled", AccountID: "second", Revision: 3, Password: secret}, "", 0},
			}
		}
		if phase == "smb-enable" {
			requests = []struct {
				request identityrpc.SMBRequest
				phase   string
				rev     uint64
			}{
				{identityrpc.SMBRequest{Action: "enable", AccountID: "second", Revision: 4}, "", 0},
				{identityrpc.SMBRequest{Action: "enable", AccountID: "second", Revision: 5}, "enabled", 7},
				{identityrpc.SMBRequest{Action: "status", AccountID: "second"}, "enabled", 7},
				{identityrpc.SMBRequest{Action: "enable", AccountID: "second", Revision: 5}, "", 0},
			}
		}
		if phase == "smb-disable" {
			requests = []struct {
				request identityrpc.SMBRequest
				phase   string
				rev     uint64
			}{
				{identityrpc.SMBRequest{Action: "disable", AccountID: "second", Revision: 6}, "", 0},
				{identityrpc.SMBRequest{Action: "disable", AccountID: "second", Revision: 7}, "disabled", 9},
				{identityrpc.SMBRequest{Action: "status", AccountID: "second"}, "disabled", 9},
			}
		}
		if phase == "smb-reenable" {
			requests = []struct {
				request identityrpc.SMBRequest
				phase   string
				rev     uint64
			}{
				{identityrpc.SMBRequest{Action: "enable", AccountID: "second", Revision: 8}, "", 0},
				{identityrpc.SMBRequest{Action: "enable", AccountID: "second", Revision: 9}, "enabled", 11},
				{identityrpc.SMBRequest{Action: "status", AccountID: "second"}, "enabled", 11},
				{identityrpc.SMBRequest{Action: "enable", AccountID: "second", Revision: 9}, "", 0},
			}
		}
		for _, test := range requests {
			dialer := net.Dialer{}
			conn, err := dialer.DialContext(ctx, "unix", identitySocket)
			if err != nil {
				return err
			}
			reply, err := identityrpc.CallSMB(ctx, conn.(*net.UnixConn), test.request)
			if err != nil {
				return err
			}
			wantCode := "ok"
			if test.phase == "" {
				wantCode = "conflict"
			}
			if reply.Code != wantCode || reply.Phase != test.phase || reply.Revision != test.rev {
				return errors.New("SMB channel fixture response mismatch")
			}
		}
		return nil
	}
	want, next := uint64(1), "group-confirmed"
	if phase == "user" {
		want, next = 3, "unix-confirmed"
	}
	type exchange struct {
		req      identityrpc.Request
		code     string
		revision uint64
		phase    string
	}
	initial := "reserved"
	if phase == "user" {
		initial = "group-confirmed"
	}
	requests := []exchange{
		{identityrpc.Request{Version: 1, Action: "status", AccountID: "managed"}, "ok", want, initial},
		{identityrpc.Request{Version: 1, Action: "step", AccountID: "managed", Revision: want}, "ok", want + 2, next},
		{identityrpc.Request{Version: 1, Action: "step", AccountID: "managed", Revision: want}, "conflict", 0, ""},
	}
	if phase == "second" {
		requests = []exchange{
			{identityrpc.Request{Version: 1, Action: "status", AccountID: "managed"}, "ok", 5, "unix-confirmed"},
			{identityrpc.Request{Version: 1, Action: "status", AccountID: "second"}, "ok", 1, "reserved"},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: "unknown", Revision: 1}, "unavailable", 0, ""},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: "managed", Revision: 5}, "conflict", 0, ""},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: "second", Revision: 1}, "ok", 3, "group-confirmed"},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: "second", Revision: 1}, "conflict", 0, ""},
			{identityrpc.Request{Version: 1, Action: "status", AccountID: "managed"}, "ok", 5, "unix-confirmed"},
			{identityrpc.Request{Version: 1, Action: "step", AccountID: "second", Revision: 3}, "ok", 5, "unix-confirmed"},
			{identityrpc.Request{Version: 1, Action: "status", AccountID: "second"}, "ok", 5, "unix-confirmed"},
		}
	}
	for _, test := range requests {
		dialer := net.Dialer{}
		conn, err := dialer.DialContext(ctx, "unix", identitySocket)
		if err != nil {
			return err
		}
		reply, err := identityrpc.Call(ctx, conn.(*net.UnixConn), test.req)
		if err != nil {
			return err
		}
		if reply.Code != test.code || reply.Revision != test.revision || reply.Phase != test.phase {
			return errors.New("channel fixture response mismatch")
		}
	}
	return nil
}
