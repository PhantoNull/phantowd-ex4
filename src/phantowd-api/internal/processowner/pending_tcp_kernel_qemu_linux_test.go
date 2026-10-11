//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Kernel query exists ONLY in this test file. No product reader, retained
// process binding, per-call PID or socket-destroy verb is introduced.
func pendingTCPKernelFixtureQEMU(ctx context.Context) (rows []pendingTCPSocketQEMU, result error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_SOCK_DIAG)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := unix.Close(fd); err != nil {
			rows = nil
			result = errors.Join(result, err)
		}
	}()
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	bound, err := unix.Getsockname(fd)
	local, ok := bound.(*unix.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, ErrUnavailable
	}
	request := make([]byte, 72) // nlmsghdr + fixed inet_diag_req_v2
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	request[16], request[17] = unix.AF_INET, unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(request[20:24], 1<<1) // Only ESTABLISHED.
	for i := 64; i < 72; i++ {
		request[i] = 255 // INET_DIAG_NOCOOKIE: no caller-selected socket/filter.
	}
	if err := unix.Sendto(fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	dump := &pendingTCPDumpQEMU{seq: 1, port: local.Pid}
	buffer := make([]byte, maxPendingTCPDatagramQEMU)
	for !dump.done {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			poll := []unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}
			if _, err := unix.Poll(poll, 20); err != nil && !errors.Is(err, unix.EINTR) {
				return nil, err
			}
			continue
		}
		sender, ok := from.(*unix.SockaddrNetlink)
		if err != nil || !ok || sender.Pid != 0 || sender.Groups != 0 || flags != 0 || n <= 0 {
			return nil, ErrUnavailable
		}
		if err := dump.consume(buffer[:n]); err != nil {
			return nil, err
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return dump.result()
}

func pendingTCPFixtureInodeQEMU(t *testing.T, connection *net.TCPConn) uint32 {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	var statErr error
	if err := raw.Control(func(fd uintptr) { statErr = unix.Fstat(int(fd), &st) }); err != nil || statErr != nil ||
		st.Mode&unix.S_IFMT != unix.S_IFSOCK || st.Ino == 0 || uint64(st.Ino) > uint64(^uint32(0)) {
		t.Fatal("fixture socket identity unavailable", err, statErr)
	}
	return uint32(st.Ino)
}

func TestPendingTCPWireActualKernelLoopbackIdentityAndClosure(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	connection, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := connection.(*net.TCPConn)
	defer client.Close()
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	clientInode, serverInode := pendingTCPFixtureInodeQEMU(t, client), pendingTCPFixtureInodeQEMU(t, server)
	local := netip.MustParseAddrPort(client.LocalAddr().String())
	peer := netip.MustParseAddrPort(client.RemoteAddr().String())
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	var originalClient, originalServer pendingTCPSocketQEMU
	for scan := 0; scan < 2; scan++ {
		rows, err := pendingTCPKernelFixtureQEMU(ctx)
		if err != nil {
			t.Fatal("actual kernel dump failed", err)
		}
		var foundClient, foundServer bool
		for _, row := range rows {
			if row.inode == clientInode && row.local == local && row.peer == peer {
				foundClient = true
				if scan == 0 {
					originalClient = row
				} else if row != originalClient {
					t.Fatal("original client socket changed")
				}
			}
			if row.inode == serverInode && row.local == peer && row.peer == local {
				foundServer = true
				if scan == 0 {
					originalServer = row
				} else if row != originalServer {
					t.Fatal("original server socket changed")
				}
			}
		}
		if !foundClient || !foundServer || originalClient.cookie == originalServer.cookie {
			t.Fatal("real reciprocal socket identities were not observed")
		}
	}
	if err := errors.Join(client.Close(), server.Close()); err != nil {
		t.Fatal("fixture socket closure failed", err)
	}
	rows, err := pendingTCPKernelFixtureQEMU(ctx)
	if err != nil {
		t.Fatal("post-close inventory failed", err)
	}
	for _, row := range rows {
		if row.inode == clientInode || row.inode == serverInode || row.cookie == originalClient.cookie || row.cookie == originalServer.cookie {
			t.Fatal("closed original socket remained established")
		}
	}
}
