// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

//go:build linux && qemu

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"time"

	"golang.org/x/sys/unix"
)

func smbLossServer(ctx context.Context, credentials []byte, peer net.Conn) error {
	if err := terminateSMBDaemon(); err != nil {
		return err
	}
	if err := waitForSMBQuarantine(ctx); err != nil {
		return err
	}
	if _, err := io.WriteString(peer, "quarantined\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(peer, "dropped\n"); err != nil {
		return err
	}
	if err := readSMBStopReply(ctx, 'R'); err != nil {
		return err
	}
	if _, err := observeHTTPS(ctx, credentials); err != nil {
		return fmt.Errorf("HTTPS after Samba loss: %w", err)
	}
	if err := errors.Join(checkBootStorage(true), checkPersistentServiceLocks(true)); err != nil {
		return err
	}
	if err := runInitHook(ctx, "start"); err == nil || ctx.Err() != nil {
		return errors.New("init accepted a replacement after Samba loss")
	}
	if err := withdrawInitGrant(ctx); err == nil || ctx.Err() != nil {
		return errors.New("withdraw accepted after Samba loss")
	}
	fmt.Println("PHANTOWD_RC0_SMB_LOSS_SERVER boot=init leader=lost ingress=quarantined https=preserved stop=review grant=retained")
	_, err := io.WriteString(peer, "verified\n")
	return err
}

func smbLossClient(ctx context.Context, peer net.Conn) error {
	if err := readNFSTestMessage(peer, "quarantined\n"); err != nil {
		return err
	}
	if err := requireSMBConnectionDrop(ctx); err != nil {
		return err
	}
	if _, err := io.WriteString(peer, "dropped\n"); err != nil {
		return err
	}
	if err := readNFSTestMessage(peer, "verified\n"); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_RC0_SMB_LOSS_CLIENT read=verified write=verified new_connection=dropped")
	return nil
}

func terminateSMBDaemon() error {
	parent, err := bootSupervisorPID()
	if err != nil {
		return err
	}
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	daemon := 0
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid <= 1 || !isSMBDaemon(pid, parent) {
			continue
		}
		if daemon != 0 {
			return errors.New("ambiguous fixture Samba leader")
		}
		daemon = pid
	}
	if daemon == 0 {
		return errors.New("fixture Samba leader missing")
	}
	fd, err := unix.PidfdOpen(daemon, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if !isSMBDaemon(daemon, parent) {
		return errors.New("fixture Samba leader changed")
	}
	return unix.PidfdSendSignal(fd, unix.SIGKILL, nil, 0)
}

func isSMBDaemon(pid, parent int) bool {
	path := "/proc/" + strconv.Itoa(pid)
	comm, err := os.ReadFile(path + "/comm")
	if err != nil || string(comm) != "smbd\n" {
		return false
	}
	status, err := os.ReadFile(path + "/status")
	if err != nil {
		return false
	}
	for _, line := range bytes.Split(status, []byte{'\n'}) {
		fields := bytes.Fields(line)
		if len(fields) == 2 && string(fields[0]) == "PPid:" {
			return string(fields[1]) == strconv.Itoa(parent)
		}
	}
	return false
}

func waitForSMBQuarantine(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	tick := time.NewTicker(150 * time.Millisecond)
	defer tick.Stop()
	for {
		out, err := exec.CommandContext(ctx, "/usr/sbin/nft", "-n", "list", "table", "inet", "phantowd_smb").Output()
		if err == nil && bytes.Contains(out, []byte("tcp dport 445 drop")) &&
			bytes.Contains(out, []byte("udp dport 445 drop")) &&
			!bytes.Contains(out, []byte("tcp dport 445 accept")) && !bytes.Contains(out, []byte("tcp flags")) {
			return nil
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Samba ingress did not enter quarantine: %w", ctx.Err())
		case <-tick.C:
		}
	}
}
