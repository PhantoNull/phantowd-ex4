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
	"reflect"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyrpc"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

const nasRPCFixture = "/run/phantowd-nas-policy-rpc"

// Two explicit channel lifetimes share one original synthetic root Owner.
// No product listener, HTTP, physical disk or service activation is involved.
func exerciseQEMUNASPolicyRPC() error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	if err := os.Mkdir(nasRPCFixture, 0710); err != nil {
		return err
	}
	if err := os.Chown(nasRPCFixture, 0, 65534); err != nil {
		return err
	}
	if err := os.Mkdir(nasRPCFixture+"/state", 0700); err != nil {
		return err
	}
	seed, err := naspolicystore.Open(nasRPCFixture + "/state")
	if err != nil {
		return err
	}
	if err := errors.Join(seed.Commit(0, qemuPersistentNASPolicy(1)), seed.Close()); err != nil {
		return err
	}
	owner, err := naspolicystore.OpenOwner(nasRPCFixture + "/state")
	if err != nil {
		return err
	}
	defer owner.Close()
	lease, err := owner.Acquire(context.Background(), 1)
	if err != nil {
		return err
	}
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: nasRPCFixture + "/channel", Net: "unix"})
	if err != nil {
		return err
	}
	defer l.Close()
	if err := errors.Join(os.Chmod(nasRPCFixture+"/channel", 0660), os.Chown(nasRPCFixture+"/channel", 0, 65534)); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	for _, phase := range []string{"held", "commit"} {
		server, err := naspolicyrpc.NewServer(owner, 65534)
		if err != nil {
			return err
		}
		cmd := exec.CommandContext(ctx, "/usr/bin/phantowd-api", "--qemu-nas-policy-client="+phase)
		cmd.Env = []string{"PATH=/usr/bin:/bin", "LC_ALL=C"}
		cmd.Dir = "/"
		cmd.Stderr = os.Stderr
		cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}, Setpgid: true}
		cmd.WaitDelay = time.Second
		if err := cmd.Start(); err != nil {
			return err
		}
		deadline, _ := ctx.Deadline()
		l.SetDeadline(deadline)
		conn, err := l.AcceptUnix()
		if err != nil {
			cmd.Process.Kill()
			cmd.Wait()
			return err
		}
		done := make(chan error, 1)
		go func() { done <- server.Serve(ctx, conn) }()
		childErr := cmd.Wait()
		conn.Close()
		serverErr := <-done
		if childErr != nil || !errors.Is(serverErr, naspolicystore.ErrReview) {
			return errors.New("NAS policy channel child or settlement failed")
		}
		if phase == "held" {
			if err := lease.Verify(ctx); err != nil {
				return err
			}
			if err := lease.Release(); err != nil {
				return err
			}
		}
	}
	got, err := owner.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(2)) {
		return errors.New("NAS policy channel did not preserve original Owner")
	}
	fmt.Println("PHANTOWD_NAS_POLICY_CHANNEL_READY kernel_peers=true root_owner=true api_uid=65534 retained_client=true original_owner=true busy=true commit=true conflict=true revision=2 scope=disposable-qemu-only")
	return owner.Close()
}

func runQEMUNASPolicyClient(phase string) error {
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" || os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || (phase != "held" && phase != "commit") {
		return errors.New("wrong NAS policy channel fixture principal or phase")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	dialer := net.Dialer{}
	conn, err := dialer.DialContext(ctx, "unix", nasRPCFixture+"/channel")
	if err != nil {
		return err
	}
	client, err := naspolicyrpc.NewClient(conn.(*net.UnixConn))
	if err != nil {
		conn.Close()
		return err
	}
	defer client.Close()
	got, err := client.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(1)) {
		return errors.New("NAS policy client initial snapshot differs")
	}
	err = client.Commit(ctx, 1, qemuPersistentNASPolicy(2))
	want := uint64(2)
	if phase == "held" {
		if !errors.Is(err, naspolicystore.ErrBusy) {
			return errors.New("NAS policy live claim was bypassed")
		}
		want = 1
	} else {
		if err != nil {
			return err
		}
		if !errors.Is(client.Commit(ctx, 1, qemuPersistentNASPolicy(2)), naspolicystore.ErrConflict) {
			return errors.New("NAS policy stale client was accepted")
		}
	}
	got, err = client.Snapshot(ctx)
	if err != nil || !reflect.DeepEqual(got, qemuPersistentNASPolicy(want)) {
		return errors.New("NAS policy client final snapshot differs")
	}
	return client.Close()
}
