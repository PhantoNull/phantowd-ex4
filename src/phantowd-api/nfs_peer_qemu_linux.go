//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
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
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
)

const peerNFSPayload = "remote-controller-nfs3-tcp-write\n"

func serveQEMUNFSPeer(ctx context.Context, command func(string, ...string) error) error {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(192, 0, 2, 1), Port: 30001})
	if err != nil {
		return err
	}
	defer listener.Close()
	deadline, ok := ctx.Deadline()
	if !ok || listener.SetDeadline(deadline) != nil {
		return errors.New("peer accept deadline unavailable")
	}
	const export = "192.0.2.2:/srv/phantowd-nfs-smoke"
	if err := command("/usr/sbin/exportfs", "-i", "-o", "rw,sync,no_subtree_check,all_squash,anonuid=65534,anongid=65534", export); err != nil {
		return err
	}
	conn, err := listener.AcceptTCP()
	if err != nil {
		return err
	}
	defer conn.Close()
	if !conn.RemoteAddr().(*net.TCPAddr).IP.Equal(net.IPv4(192, 0, 2, 2)) || conn.SetDeadline(deadline) != nil {
		return errors.New("unexpected peer")
	}
	message := make([]byte, len("unmounted\n"))
	if _, err := io.ReadFull(conn, message); err != nil || string(message) != "unmounted\n" {
		return errors.New("remote unmount not confirmed")
	}
	data, err := os.ReadFile("/srv/phantowd-nfs-smoke/peer-write")
	if err != nil || string(data) != peerNFSPayload {
		return errors.New("remote write differs at server")
	}
	if err := command("/usr/sbin/exportfs", "-u", export); err != nil {
		return err
	}
	if n, err := io.WriteString(conn, "verified\n"); err != nil || n != len("verified\n") {
		return errors.New("peer confirmation incomplete")
	}
	return errors.Join(conn.Close(), listener.Close())
}

func runQEMUNFSPeer(mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if mode == "peer-server" {
		var previous *nfskernel.ControllerQEMU
		if err := runQEMUNFSKernelCycle(ctx, 1, &previous, true); err != nil {
			return err
		}
		fmt.Println("PHANTOWD_NFS_PEER_SERVER_READY kernel_backend=true activation=true remote_bytes=true teardown=clean scope=isolated-two-guest-only")
		return nil
	}
	if !nfskernel.PeerClientQEMU() {
		return errors.New("separate NFS client requires fixed QEMU role")
	}
	var conn net.Conn
	for {
		var err error
		conn, err = (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp4", "192.0.2.1:30001")
		if err == nil {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(200 * time.Millisecond):
		}
	}
	defer conn.Close()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return err
	}
	command := func(name string, args ...string) error {
		bounded, done := context.WithTimeout(ctx, 10*time.Second)
		defer done()
		out, err := exec.CommandContext(bounded, name, args...).CombinedOutput()
		if err != nil {
			return fmt.Errorf("peer %s: %w: %s", name, err, out)
		}
		return nil
	}
	const root = "/run/nfs-peer-client"
	const source = "192.0.2.1:/srv/phantowd-nfs-smoke"
	if err := os.Mkdir(root, 0700); err != nil {
		return err
	}
	if err := command("/bin/mount", "-t", "nfs", "-o", "vers=3,proto=tcp,mountproto=tcp,nolock,soft,timeo=5,retrans=1", source, root); err != nil {
		return err
	}
	mounts, err := os.ReadFile("/proc/mounts")
	found := 0
	for _, line := range strings.Split(string(mounts), "\n") {
		f := strings.Fields(line)
		if len(f) == 6 && f[0] == source && f[1] == root && f[2] == "nfs" && strings.Contains(","+f[3]+",", ",vers=3,") && strings.Contains(","+f[3]+",", ",proto=tcp,") {
			found++
		}
	}
	if err != nil || found != 1 {
		return errors.New("remote NFSv3/TCP mount not observed")
	}
	data, err := os.ReadFile(root + "/marker")
	if err != nil || !bytes.Equal(data, []byte("phantowd-qemu-nfs-smoke-v1\n")) {
		return errors.New("remote marker differs")
	}
	f, err := os.OpenFile(root+"/peer-write", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.WriteString(peerNFSPayload)
	syncErr, closeErr := f.Sync(), f.Close()
	if n != len(peerNFSPayload) || writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("remote write completion uncertain")
	}
	data, err = os.ReadFile(root + "/peer-write")
	if err != nil || string(data) != peerNFSPayload {
		return errors.New("remote client readback differs")
	}
	if err := command("/bin/umount", root); err != nil {
		return err
	}
	mounts, err = os.ReadFile("/proc/mounts")
	if err != nil || strings.Contains(string(mounts), " "+root+" ") {
		return errors.New("remote mount still present")
	}
	if n, err := io.WriteString(conn, "unmounted\n"); err != nil || n != len("unmounted\n") {
		return errors.New("remote unmount report incomplete")
	}
	ack := make([]byte, len("verified\n"))
	if _, err := io.ReadFull(conn, ack); err != nil || string(ack) != "verified\n" {
		return errors.New("server byte confirmation missing")
	}
	if err := conn.Close(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_PEER_CLIENT_READY protocol=nfs3 transport=tcp read=true write=true fsync=true unmount=clean scope=isolated-two-guest-only")
	return nil
}
