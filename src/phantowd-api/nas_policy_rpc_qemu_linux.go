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
// HTTPS is guest-loopback-only; no product listener, disk or service activation.
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
	if err := owner.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NAS_POLICY_CHANNEL_READY kernel_peers=true root_owner=true api_uid=65534 retained_client=true original_owner=true busy=true commit=true conflict=true revision=2 scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NAS_POLICY_HTTP_CHANNEL_READY api_uid=65534 https=true retained_client=true root_owner=true busy=true commit=true conflict=true readback=true parent_verified=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_NAS_POLICY_API_ROUTER_READY api_uid=65534 startup_factory=true protected_lookup=true router=true legacy_refused=true plaintext_refused=true closed_refusal=true scope=disposable-qemu-only")
	return nil
}

func runQEMUNASPolicyClient(phase string) error {
	if runtime.GOARCH != "arm" || strings.Split(buildARMLevel(), ",")[0] != "5" || os.Getuid() != 65534 || os.Geteuid() != 65534 || os.Getgid() != 65534 || (phase != "held" && phase != "commit") {
		return errors.New("wrong NAS policy channel fixture principal or phase")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	management, err := newQEMUNASPolicyHTTPAt(nil, nasRPCFixture+"/channel")
	if err != nil {
		return err
	}
	defer management.Close()
	if err := management.exchange(ctx, nil, 200); err != nil {
		return err
	}
	status := 200
	if phase == "held" {
		status = 503
	}
	next := qemuPersistentNASPolicy(2)
	if err := management.exchange(ctx, &next, status); err != nil {
		return err
	}
	if phase == "commit" {
		if err := management.exchange(ctx, &next, 409); err != nil {
			return err
		}
	}
	if err := management.exchange(ctx, nil, 200); err != nil {
		return err
	}
	if err := errors.Join(management.closeTransport(), management.closeTransport()); err != nil {
		return err
	}
	if err := management.exchange(ctx, nil, 503); err != nil {
		return err
	}
	return management.Close()
}
