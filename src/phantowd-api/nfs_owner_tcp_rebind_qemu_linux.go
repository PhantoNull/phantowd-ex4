//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"
)

// Hold one disposable peer until NFSD sends FIN. This makes the previous
// lifetime's server-side TIME_WAIT observable before the next bind.
func stopOwnerWithServerTimeWaitQEMU(ctx context.Context, stop func(context.Context) error) (string, error) {
	const endpoint = "127.0.0.1:2049"
	listener, err := net.Listen("tcp4", endpoint)
	if listener != nil {
		return "", errors.Join(errors.New("NFS duplicate live listener was admitted"), listener.Close())
	}
	if !errors.Is(err, syscall.EADDRINUSE) {
		return "", errors.Join(errors.New("NFS duplicate bind did not report EADDRINUSE"), err)
	}

	peer, err := (&net.Dialer{}).DialContext(ctx, "tcp4", endpoint)
	if err != nil {
		return "", err
	}
	// The only explicit close happens after the server has sent FIN.
	defer func() {
		if peer != nil {
			_ = peer.Close()
		}
	}()
	addr, ok := peer.LocalAddr().(*net.TCPAddr)
	if !ok || addr.Port < 1 || addr.Port > 65535 || !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) {
		return "", errors.New("NFS rebind peer endpoint differs")
	}
	peerTuple := fmt.Sprintf("0100007F:%04X", addr.Port)
	if err := waitOwnerNFSTCPStateQEMU(ctx, peerTuple, "01"); err != nil {
		return "", fmt.Errorf("NFSD did not accept the loopback peer: %w", err)
	}
	if err := stop(ctx); err != nil {
		return "", err
	}
	deadline := time.Now().Add(2 * time.Second)
	if parent, ok := ctx.Deadline(); ok && parent.Before(deadline) {
		deadline = parent
	}
	if err := peer.SetReadDeadline(deadline); err != nil {
		return "", err
	}
	var one [1]byte
	if n, err := peer.Read(one[:]); n != 0 || err != io.EOF {
		return "", errors.Join(errors.New("NFSD did not close the peer first"), err)
	}
	err = peer.Close()
	peer = nil
	if err != nil {
		return "", err
	}
	if err := waitOwnerNFSTCPStateQEMU(ctx, peerTuple, "06"); err != nil {
		return "", fmt.Errorf("NFSD server-side TIME_WAIT missing: %w", err)
	}
	return peerTuple, nil
}

// In the pinned Linux guest /proc/net/tcp reports a nonzero inode once the
// server socket is accepted. A server-side TIME_WAIT entry has no live inode.
func ownerNFSTCPStateQEMU(peerTuple, state string) (bool, error) {
	table, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		return false, err
	}
	for _, line := range strings.Split(string(table), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 10 && fields[1] == "0100007F:0801" &&
			fields[2] == peerTuple && fields[3] == state &&
			(fields[9] != "0") == (state == "01") {
			return true, nil
		}
	}
	return false, nil
}

func waitOwnerNFSTCPStateQEMU(parent context.Context, peerTuple, state string) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	poll := time.NewTicker(10 * time.Millisecond)
	defer poll.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		present, err := ownerNFSTCPStateQEMU(peerTuple, state)
		if err != nil || present {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-poll.C:
		}
	}
}
