//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

type qemuNFSNetlinkReader struct {
	fd             int
	port, sequence uint32
	deadline       time.Time
}

func (r *qemuNFSNetlinkReader) query(ctx context.Context, family uint16, command byte) (uint16, []byte, error) {
	if ctx == nil || ctx.Err() != nil || r.fd < 0 || r.port == 0 || !time.Now().Before(r.deadline) || r.sequence == ^uint32(0) {
		return 0, nil, errQEMUNFSNetlink
	}
	r.sequence++
	request, err := qemuNFSNetlinkRequest(family, command, r.sequence)
	if err != nil || unix.Sendto(r.fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return 0, nil, errQEMUNFSNetlink
	}
	reply := qemuNFSNetlinkReply{family: family, command: command, sequence: r.sequence, port: r.port}
	buffer := make([]byte, 65536)
	for !reply.done {
		if ctx.Err() != nil || !time.Now().Before(r.deadline) {
			return 0, nil, errQEMUNFSNetlink
		}
		wait := min(50*time.Millisecond, time.Until(r.deadline))
		poll := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, max(1, int(wait.Milliseconds())))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || poll[0].Revents & ^int16(unix.POLLIN) != 0 {
			return 0, nil, errQEMUNFSNetlink
		}
		if poll[0].Revents == 0 {
			continue
		}
		if ctx.Err() != nil || !time.Now().Before(r.deadline) {
			return 0, nil, errQEMUNFSNetlink
		}
		n, oob, flags, sender, err := unix.Recvmsg(r.fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) {
			continue
		}
		peer, ok := sender.(*unix.SockaddrNetlink)
		if err != nil || !ok || peer.Pid != 0 || peer.Groups != 0 || oob != 0 || flags != 0 || n <= 0 || n > len(buffer) || reply.consume(buffer[:n]) != nil {
			return 0, nil, errQEMUNFSNetlink
		}
	}
	if ctx.Err() != nil || !time.Now().Before(r.deadline) {
		return 0, nil, errQEMUNFSNetlink
	}
	return reply.result()
}

// Only called within the existing guarded, NIC-less reboot fixture. Read-only
// requests, no module-name lookup, namespace change, backend selection or HTTP.
// Samples are diagnostic; they are not an atomic census, Owner or stop lease.
func checkQEMUNFSNetlinkProfile(running bool) (result error) {
	if os.Geteuid() != 0 || runQEMUNFSTest("verify-disk") != nil {
		return errQEMUNFSNetlink
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	deadline, _ := ctx.Deadline()
	defer func() {
		if ctx.Err() != nil || !time.Now().Before(deadline) {
			result = errors.Join(result, errQEMUNFSNetlink)
		}
	}()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	const namespace = "/proc/thread-self/ns/net"
	ns, err := unix.Open(namespace, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return errQEMUNFSNetlink
	}
	defer func() {
		if unix.Close(ns) != nil {
			result = errors.Join(result, errQEMUNFSNetlink)
		}
	}()
	var original unix.Stat_t
	if unix.Fstat(ns, &original) != nil || original.Ino == 0 {
		return errQEMUNFSNetlink
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_GENERIC)
	if err != nil {
		return errQEMUNFSNetlink
	}
	defer func() {
		if unix.Close(fd) != nil {
			result = errors.Join(result, errQEMUNFSNetlink)
		}
	}()
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return errQEMUNFSNetlink
	}
	bound, err := unix.Getsockname(fd)
	local, ok := bound.(*unix.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		return errQEMUNFSNetlink
	}
	reader := qemuNFSNetlinkReader{fd: fd, port: local.Pid, deadline: deadline}
	checkNamespace := func() error {
		var current unix.Stat_t
		if ctx.Err() != nil || unix.Stat(namespace, &current) != nil || current.Dev != original.Dev || current.Ino != original.Ino {
			return errQEMUNFSNetlink
		}
		return nil
	}
	if err := checkNamespace(); err != nil {
		return err
	}
	family, _, err := reader.query(ctx, 16, 3)
	if err != nil {
		return errors.New("NFS fixture registered-family census unavailable")
	}
	var values [3][]byte
	for index, command := range []byte{3, 5, 7} {
		_, values[index], err = reader.query(ctx, family, command)
		if err != nil {
			return errors.New("NFS fixture correlated GET unavailable")
		}
	}
	confirmed, _, err := reader.query(ctx, 16, 3)
	if err != nil || confirmed != family || checkNamespace() != nil {
		return errQEMUNFSNetlink
	}
	return validateQEMUNFSNetlinkProfile(values[0], values[1], values[2], running)
}
