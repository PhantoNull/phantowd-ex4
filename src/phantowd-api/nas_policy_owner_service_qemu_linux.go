//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyrpc"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

const nasBootRoot = "/run/phantowd-nas-policy-boot"

// Fixed disposable provider: no caller-selected paths, identities or commands.
func runQEMUNASPolicyOwnerService() (runErr error) {
	if err := guardQEMUIdentityOwnerService(); err != nil {
		return err
	}
	var fs unix.Statfs_t
	if ensureQEMUOwnerDirectory("/run", 0755, 0) != nil || unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("NAS provider requires protected volatile /run")
	}
	uid, gid, err := qemuIdentityOwnerAPIIdentity()
	if err != nil {
		return err
	}
	if err := os.Mkdir(nasBootRoot, 0710); err != nil {
		return err // Never adopt or repair an earlier lifetime.
	}
	if err := errors.Join(os.Chown(nasBootRoot, 0, int(gid)), os.Chmod(nasBootRoot, 0710),
		ensureQEMUOwnerDirectory(nasBootRoot+"/state", 0700, 0)); err != nil {
		return err
	}
	seed, err := naspolicystore.Open(nasBootRoot + "/state")
	if err != nil {
		return err
	}
	if err := errors.Join(seed.Commit(0, qemuPersistentNASPolicy(1)), seed.Close()); err != nil {
		return err
	}
	confirmed, err := json.Marshal(qemuPersistentNASPolicy(1))
	if err != nil {
		return err
	}
	const installation = "66666666666666666666666666666666"
	if err := writeQEMUStateFixture(nasBootRoot+"/state/nas-evidence.json", []byte(`{"format":"phantowd-nas-evidence-container","schema_version":1,"installation_id":"`+installation+`"}`)); err != nil {
		return err
	}
	owner, err := naspolicystore.OpenConfirmedOwner(context.Background(), nasBootRoot+"/state", installation, confirmed)
	if err != nil {
		return err
	}
	defer func() { runErr = errors.Join(runErr, owner.Close()) }()
	server, err := naspolicyrpc.NewServer(owner, uid)
	if err != nil {
		return err
	}
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: nasBootRoot + "/channel", Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := errors.Join(os.Chown(nasBootRoot+"/channel", 0, int(gid)), os.Chmod(nasBootRoot+"/channel", 0660)); err != nil {
		return err
	}
	var parent, socket unix.Stat_t
	if unix.Lstat(nasBootRoot, &parent) != nil || !nasPolicyParentSafe(parent, gid) ||
		unix.Lstat(nasBootRoot+"/channel", &socket) != nil || !nasPolicySocketSafe(socket, parent, gid) {
		return errors.New("NAS provider socket metadata refused")
	}
	transport, err := qemuNASMainTLSAt(nasBootRoot, int(uid), int(gid))
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go func() { <-ctx.Done(); listener.Close() }()
	const ready = "PHANTOWD_NAS_PROVIDER_READY root=true directory_mode=0710 socket_mode=0660 runtime=run scope=qemu-only\n"
	if err := writeQEMUStateFixture(nasBootRoot+"/ready.pending", []byte(ready)); err != nil {
		return err
	}
	if err := os.Rename(nasBootRoot+"/ready.pending", nasBootRoot+"/ready"); err != nil {
		return err
	}
	conn, err := listener.AcceptUnix() // Exactly one stream; never accept again.
	if err != nil {
		return err
	}
	err = server.Serve(ctx, conn)
	if ctx.Err() != nil && errors.Is(err, naspolicystore.ErrReview) {
		return nil
	}
	return err
}
