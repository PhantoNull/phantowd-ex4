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
	"os"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// Kernel query exists ONLY in this test file. No product reader, retained
// process binding, per-call PID or socket-destroy verb is introduced.
func pendingTCPKernelFixtureQEMU(ctx context.Context) (rows []pendingTCPSocketQEMU, result error) {
	return pendingTCPKernelFixtureAtSendQEMU(ctx, nil)
}

// The optional notification is test synchronization only: after the real fixed
// request has been sent, before its first receive. It selects no socket/PID.
func pendingTCPKernelFixtureAtSendQEMU(ctx context.Context, sent func()) (rows []pendingTCPSocketQEMU, result error) {
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
	if sent != nil {
		sent()
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

// Independent descriptor observations, not observations from a second dump.
// This helper is test-only and retains no descriptor/process authority. The
// fixture never binds a device, so its separately checked empty SO_BINDTODEVICE
// corresponds to the expected zero interface index.
func pendingTCPFixtureDescriptorQEMU(t *testing.T, connection *net.TCPConn) pendingTCPSocketQEMU {
	t.Helper()
	raw, err := connection.SyscallConn()
	if err != nil {
		t.Fatal(err)
	}
	var st unix.Stat_t
	var cookie uint64
	var local, peer unix.Sockaddr
	var device string
	var inspectErr error
	if err := raw.Control(func(fd uintptr) {
		inspectErr = unix.Fstat(int(fd), &st)
		if inspectErr == nil {
			cookie, inspectErr = unix.GetsockoptUint64(int(fd), unix.SOL_SOCKET, unix.SO_COOKIE)
		}
		if inspectErr == nil {
			local, inspectErr = unix.Getsockname(int(fd))
		}
		if inspectErr == nil {
			peer, inspectErr = unix.Getpeername(int(fd))
		}
		if inspectErr == nil {
			device, inspectErr = unix.GetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE)
		}
	}); err != nil || inspectErr != nil || st.Mode&unix.S_IFMT != unix.S_IFSOCK ||
		st.Ino == 0 || uint64(st.Ino) > uint64(^uint32(0)) || cookie == 0 || cookie == ^uint64(0) || device != "" {
		t.Fatal("fixture socket descriptor identity unavailable", err, inspectErr)
	}
	address := func(source unix.Sockaddr) netip.AddrPort {
		a, ok := source.(*unix.SockaddrInet4)
		if !ok || a.Port <= 0 || a.Port > 65535 {
			t.Fatal("fixture socket address unavailable")
		}
		return netip.AddrPortFrom(netip.AddrFrom4(a.Addr), uint16(a.Port))
	}
	return pendingTCPSocketQEMU{
		inode: uint32(st.Ino), cookie: cookie, uid: st.Uid,
		local: address(local), peer: address(peer),
	}
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
	clientExpected, serverExpected := pendingTCPFixtureDescriptorQEMU(t, client), pendingTCPFixtureDescriptorQEMU(t, server)
	clientInode, serverInode := clientExpected.inode, serverExpected.inode
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
		ownedRows, ownedErr := pendingTCPKernelQEMU(ctx)
		if ownedErr != nil {
			t.Fatal("bounded containing-reader dump failed", ownedErr)
		}
		matched := 0
		for _, row := range ownedRows {
			if row.inode == clientInode {
				if row != clientExpected {
					t.Fatal("containing-reader client oracle mismatch")
				}
				matched++
			}
			if row.inode == serverInode {
				if row != serverExpected {
					t.Fatal("containing-reader server oracle mismatch")
				}
				matched++
			}
		}
		if matched != 2 {
			t.Fatal("containing reader did not publish both original descriptor identities")
		}
		var foundClient, foundServer bool
		for _, row := range rows {
			if row.inode == clientInode && row.local == local && row.peer == peer {
				if row != clientExpected {
					t.Fatal("kernel row disagrees with original client descriptor")
				}
				foundClient = true
				if scan == 0 {
					originalClient = row
				} else if row != originalClient {
					t.Fatal("original client socket changed")
				}
			}
			if row.inode == serverInode && row.local == peer && row.peer == local {
				if row != serverExpected {
					t.Fatal("kernel row disagrees with original server descriptor")
				}
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

func pendingTCPFixturePairQEMU(t *testing.T) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	return pendingTCPFixturePairAtQEMU(t, pendingTCPFixtureListenerQEMU(t))
}

func pendingTCPFixtureListenerQEMU(t *testing.T) *net.TCPListener {
	t.Helper()
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	if err := listener.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return listener
}

func pendingTCPFixturePairAtQEMU(t *testing.T, listener *net.TCPListener) (*net.TCPConn, *net.TCPConn) {
	t.Helper()
	connection, err := (&net.Dialer{Timeout: 2 * time.Second}).Dial("tcp4", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	client := connection.(*net.TCPConn)
	t.Cleanup(func() { _ = client.Close() })
	server, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close() })
	return client, server
}

func pendingTCPFixtureFDCountQEMU(t *testing.T) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	return len(entries)
}

func TestPendingTCPWireActualKernelDistinctConnectionsAndConcurrentQueries(t *testing.T) {
	listener := pendingTCPFixtureListenerQEMU(t)
	clientA, serverA := pendingTCPFixturePairAtQEMU(t, listener)
	clientB, serverB := pendingTCPFixturePairAtQEMU(t, listener)
	expected := []pendingTCPSocketQEMU{
		pendingTCPFixtureDescriptorQEMU(t, clientA), pendingTCPFixtureDescriptorQEMU(t, serverA),
		pendingTCPFixtureDescriptorQEMU(t, clientB), pendingTCPFixtureDescriptorQEMU(t, serverB),
	}
	for i, a := range expected {
		for _, b := range expected[i+1:] {
			if a.inode == b.inode || a.cookie == b.cookie || a.local == b.local && a.peer == b.peer {
				t.Fatal("different owned fixture sockets have indistinguishable identities")
			}
		}
	}
	if expected[0].peer != expected[2].peer || expected[1].local != expected[3].local {
		t.Fatal("fixture connections did not use the same server endpoint")
	}
	for _, row := range expected {
		if row.uid != expected[0].uid {
			t.Fatal("fixture sockets did not use the same UID")
		}
	}
	before := pendingTCPFixtureFDCountQEMU(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 4 {
				rows, err := pendingTCPKernelFixtureQEMU(ctx)
				if err != nil {
					t.Error("concurrent kernel query failed", err)
					return
				}
				for _, want := range expected {
					matches := 0
					for _, row := range rows {
						if row == want {
							matches++
						}
					}
					if matches != 1 {
						t.Error("query did not uniquely observe original descriptor identity")
					}
				}
			}
		})
	}
	wg.Wait()
	if after := pendingTCPFixtureFDCountQEMU(t); after != before {
		t.Fatal("queries leaked descriptors", before, after)
	}
	if err := errors.Join(clientA.Close(), serverA.Close()); err != nil {
		t.Fatal(err)
	}
	rows, err := pendingTCPKernelFixtureQEMU(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, original := range expected {
		found := 0
		for _, row := range rows {
			if row.cookie == original.cookie || row.inode == original.inode {
				if row != original {
					t.Fatal("original socket identity changed")
				}
				found++
			}
		}
		want := 0
		if original == expected[2] || original == expected[3] {
			want = 1
		}
		if found != want {
			t.Fatal("closing first pair changed observation of second pair", found, want)
		}
	}
}

func TestPendingTCPWireActualKernelCanceledQueriesReleaseDescriptors(t *testing.T) {
	pendingTCPFixturePairQEMU(t) // Initialize the Go network poller before the census.
	before := pendingTCPFixtureFDCountQEMU(t)
	if rows, err := pendingTCPKernelFixtureQEMU(nil); !errors.Is(err, ErrInvalid) || rows != nil {
		t.Fatal("nil context was not refused", rows, err)
	}
	for range 32 {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if rows, err := pendingTCPKernelFixtureQEMU(ctx); !errors.Is(err, context.Canceled) || rows != nil {
			t.Fatal("canceled query exposed an observation", rows, err)
		}
		ctx, cancel = context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
		if rows, err := pendingTCPKernelFixtureQEMU(ctx); !errors.Is(err, context.DeadlineExceeded) || rows != nil {
			cancel()
			t.Fatal("expired query exposed an observation", rows, err)
		}
		cancel()
	}
	for range 16 {
		ctx, cancel := context.WithCancel(context.Background())
		sent := false
		rows, err := pendingTCPKernelFixtureAtSendQEMU(ctx, func() {
			sent = true
			cancel()
		})
		cancel()
		if !sent || !errors.Is(err, context.Canceled) || rows != nil {
			t.Fatal("cancellation after the real kernel request exposed rows", sent, rows, err)
		}
	}
	if after := pendingTCPFixtureFDCountQEMU(t); after != before {
		t.Fatal("refused queries leaked descriptors", before, after)
	}
}
