// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package networkinventory

import (
	"context"
	"encoding/binary"
	"errors"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

const namespacePath = "/proc/thread-self/ns/net"
const socketBudget = 5 * time.Second

type kernelReader struct {
	fd        int
	port, seq uint32
	deadline  time.Time
}

// Collect opens only fixed namespace metadata and one dump-only route socket.
// It performs no network configuration and needs no administrative capability.
func Collect(ctx context.Context) (result *Observation, resultErr error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, ErrUnavailable
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	nsfd, err := unix.Open(namespacePath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if unix.Close(nsfd) != nil {
			result = nil
			resultErr = ErrUnavailable
		}
	}()
	var pin unix.Stat_t
	if unix.Fstat(nsfd, &pin) != nil || pin.Ino == 0 {
		return nil, ErrUnavailable
	}
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC|unix.SOCK_NONBLOCK, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, ErrUnavailable
	}
	defer func() {
		if unix.Close(fd) != nil {
			result = nil
			resultErr = ErrUnavailable
		}
	}()
	if unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil ||
		unix.SetsockoptInt(fd, unix.SOL_NETLINK, unix.NETLINK_GET_STRICT_CHK, 1) != nil {
		return nil, ErrUnavailable
	}
	bound, err := unix.Getsockname(fd)
	local, ok := bound.(*unix.SockaddrNetlink)
	if err != nil || !ok || local.Pid == 0 || local.Groups != 0 {
		return nil, ErrUnavailable
	}
	r := &kernelReader{fd: fd, port: local.Pid, deadline: time.Now().Add(socketBudget)}
	current, err := r.namespace()
	if err != nil || current != (namespaceID{uint64(pin.Dev), uint64(pin.Ino)}) {
		return nil, ErrUnavailable
	}
	return observe(ctx, r)
}

func (*kernelReader) namespace() (namespaceID, error) {
	var st unix.Stat_t
	if unix.Stat(namespacePath, &st) != nil || st.Ino == 0 {
		return namespaceID{}, ErrUnavailable
	}
	return namespaceID{uint64(st.Dev), uint64(st.Ino)}, nil
}

func (r *kernelReader) read(ctx context.Context) (snapshot, error) {
	links, err := r.query(ctx, unix.RTM_GETLINK, unix.RTM_NEWLINK)
	if err != nil {
		return snapshot{}, ErrUnavailable
	}
	addresses, err := r.query(ctx, unix.RTM_GETADDR, unix.RTM_NEWADDR)
	if err != nil {
		return snapshot{}, ErrUnavailable
	}
	return snapshot{links: links.links, addresses: addresses.addresses}, nil
}

func (r *kernelReader) query(ctx context.Context, request, response uint16) (dump, error) {
	if !r.available(ctx) {
		return dump{}, ErrUnavailable
	}
	size := 32
	if request == unix.RTM_GETADDR {
		size = 24
	} else if request != unix.RTM_GETLINK {
		return dump{}, ErrUnavailable
	}
	r.seq++
	message := make([]byte, size)
	binary.NativeEndian.PutUint32(message[:4], uint32(size))
	binary.NativeEndian.PutUint16(message[4:6], request)
	binary.NativeEndian.PutUint16(message[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(message[8:12], r.seq)
	// AF_UNSPEC, zeroed family-specific fields, no selectors/attributes/ACK.
	if unix.Sendto(r.fd, message, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}) != nil {
		return dump{}, ErrUnavailable
	}
	d := dump{seq: r.seq, port: r.port, kind: response, links: []link{}, addresses: []ipAddress{}}
	buffer := make([]byte, maxDatagramBytes)
	for !d.done {
		if !r.available(ctx) {
			return dump{}, ErrUnavailable
		}
		wait := time.Until(r.deadline)
		if wait > 50*time.Millisecond {
			wait = 50 * time.Millisecond
		}
		poll := []unix.PollFd{{Fd: int32(r.fd), Events: unix.POLLIN}}
		_, err := unix.Poll(poll, max(1, int(wait.Milliseconds())))
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil || poll[0].Revents & ^int16(unix.POLLIN) != 0 {
			return dump{}, ErrUnavailable
		}
		if poll[0].Revents == 0 {
			continue
		}
		if !r.available(ctx) {
			return dump{}, ErrUnavailable
		}
		n, oob, flags, sender, err := unix.Recvmsg(r.fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EINTR) {
			continue
		}
		peer, ok := sender.(*unix.SockaddrNetlink)
		if err != nil || !ok || peer.Pid != 0 || peer.Groups != 0 || oob != 0 || flags != 0 || n <= 0 || n > len(buffer) || d.consume(buffer[:n]) != nil {
			return dump{}, ErrUnavailable
		}
	}
	if !r.available(ctx) {
		return dump{}, ErrUnavailable
	}
	return d, nil
}

func (r *kernelReader) available(ctx context.Context) bool {
	return ctx != nil && ctx.Err() == nil && time.Now().Before(r.deadline)
}
