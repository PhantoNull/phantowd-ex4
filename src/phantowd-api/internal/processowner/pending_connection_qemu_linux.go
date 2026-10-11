//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// A private connection witness, not an SMB handle/request or write grant.
// All references survive uncertainty and close only after owned-group settlement.
type pendingConnectionQEMU struct {
	client, peer         *os.File
	namespaces           []*os.File // original client net/mnt and peer net/mnt
	clientStat, peerStat pendingProcGenerationQEMU
	pair                 pendingTCPPairQEMU
}

type pendingProcGenerationQEMU struct {
	pid, parent, group int
	start              uint64
}

func pendingProcStatQEMU(data []byte) (pendingProcGenerationQEMU, error) {
	var result pendingProcGenerationQEMU
	if len(data) == 0 || len(data) > 4096 {
		return result, ErrUnavailable
	}
	text := string(data)
	end := strings.LastIndex(text, ") ")
	begin := strings.Index(text, " (")
	if begin < 1 || end <= begin {
		return result, ErrUnavailable
	}
	fields := strings.Fields(text[end+2:])
	if len(fields) < 20 || (fields[0] != "S" && fields[0] != "R" && fields[0] != "D") {
		return result, ErrUnavailable
	}
	values := []*int{&result.pid, &result.parent, &result.group}
	for index, token := range []string{text[:begin], fields[1], fields[2]} {
		value, err := strconv.ParseUint(token, 10, 31)
		if err != nil || value == 0 || (index == 0 && value <= 1) || strconv.FormatUint(value, 10) != token {
			return pendingProcGenerationQEMU{}, ErrUnavailable
		}
		*values[index] = int(value)
	}
	start, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || start == 0 || strconv.FormatUint(start, 10) != fields[19] {
		return pendingProcGenerationQEMU{}, ErrUnavailable
	}
	result.start = start
	return result, nil
}

func pendingProcReadQEMU(proc *os.File, name string, limit int64) ([]byte, error) {
	fd, err := unix.Openat(int(proc.Fd()), name, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "original-process-observation")
	data, readErr := io.ReadAll(io.LimitReader(file, limit+1))
	err = errors.Join(readErr, file.Close())
	if err != nil || int64(len(data)) > limit {
		return nil, errors.Join(ErrUnavailable, err)
	}
	return data, nil
}

func pendingProcGenerationReadQEMU(proc *os.File) (pendingProcGenerationQEMU, error) {
	data, err := pendingProcReadQEMU(proc, "stat", 4096)
	if err != nil {
		return pendingProcGenerationQEMU{}, err
	}
	return pendingProcStatQEMU(data)
}

func retainPendingProcQEMU(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, err
	}
	fd := -1
	var duplicateErr error
	err = raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) })
	if err != nil || duplicateErr != nil || fd < 0 {
		return nil, errors.Join(ErrInvalid, err, duplicateErr)
	}
	file := os.NewFile(uintptr(fd), "original-peer-process")
	var info unix.Stat_t
	var fs unix.Statfs_t
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 || flags&unix.O_DIRECTORY == 0 ||
		unix.Fstat(fd, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR || unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return file, errors.Join(ErrInvalid, err) // Retained by the partial reviewed binding.
	}
	return file, nil
}

func pendingNamespaceQEMU(proc *os.File, name string) (*os.File, error) {
	// Fixed procfs namespace magic links, never a caller-selected pathname.
	fd, err := unix.Openat(int(proc.Fd()), "ns/"+name, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "original-process-namespace")
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.NSFS_MAGIC {
		return file, ErrUnavailable // Caller retains this opened reference on refusal.
	}
	return file, nil
}

func samePendingNamespaceQEMU(file *os.File, proc *os.File, name string) error {
	var held, actual unix.Stat_t
	if file == nil || proc == nil || unix.Fstat(int(file.Fd()), &held) != nil ||
		unix.Fstatat(int(proc.Fd()), "ns/"+name, &actual, 0) != nil || held.Dev != actual.Dev || held.Ino != actual.Ino {
		return ErrUnavailable
	}
	return nil
}

func pendingSocketLinkQEMU(link string) (uint32, error) {
	if !strings.HasPrefix(link, "socket:[") || !strings.HasSuffix(link, "]") {
		return 0, ErrInvalid
	}
	token := link[8 : len(link)-1]
	value, err := strconv.ParseUint(token, 10, 32)
	if err != nil || value == 0 || strconv.FormatUint(value, 10) != token {
		return 0, ErrUnavailable
	}
	return uint32(value), nil
}

func pendingProcessSocketsQEMU(ctx context.Context, proc *os.File) (sockets []uint32, result error) {
	if ctx == nil || proc == nil {
		return nil, ErrInvalid
	}
	fd, err := unix.Openat(int(proc.Fd()), "fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "original-process-fd-census")
	defer func() {
		if err := directory.Close(); err != nil {
			sockets = nil
			result = errors.Join(result, err)
		}
	}()
	names, err := directory.Readdirnames(257)
	if err != nil && err != io.EOF || len(names) > 256 {
		return nil, ErrUnavailable
	}
	if extra, err := directory.Readdirnames(1); len(extra) != 0 || err != io.EOF {
		return nil, ErrUnavailable
	}
	seen := make(map[uint32]bool)
	buffer := make([]byte, 4097)
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		value, err := strconv.ParseUint(name, 10, 31)
		if err != nil || strconv.FormatUint(value, 10) != name {
			return nil, ErrUnavailable
		}
		n, err := unix.Readlinkat(fd, name, buffer)
		if err != nil || n <= 0 || n >= len(buffer) {
			return nil, ErrUnavailable
		}
		link := string(buffer[:n])
		if strings.HasPrefix(link, "socket:") {
			inode, err := pendingSocketLinkQEMU(link)
			if err != nil || seen[inode] {
				return nil, ErrUnavailable
			} // Ambiguous aliases refuse.
			seen[inode] = true
			sockets = append(sockets, inode)
		}
	}
	return sockets, ctx.Err()
}

func (w *pendingConnectionQEMU) recheckProcessesQEMU(c *PendingClientQEMU) error {
	if w == nil || w.client == nil || w.peer == nil || len(w.namespaces) != 4 || c == nil || len(c.pins) != 3 {
		return ErrUnavailable
	}
	client, err := pendingProcGenerationReadQEMU(w.client)
	peer, peerErr := pendingProcGenerationReadQEMU(w.peer)
	if err != nil || peerErr != nil || client != w.clientStat || peer != w.peerStat ||
		c.process == nil || c.process.exited() || client.pid != c.process.pid || client.parent != os.Getpid() || client.group != client.pid {
		return errors.Join(ErrUnavailable, err, peerErr)
	}
	actual, err := os.Stat("/proc/self/fd/" + strconv.FormatUint(uint64(w.client.Fd()), 10) + "/exe")
	expected, expectedErr := c.pins[2].Stat()
	if err != nil || expectedErr != nil || !os.SameFile(actual, expected) {
		return ErrUnavailable
	}
	status, err := pendingProcReadQEMU(w.client, "status", 64<<10)
	if err != nil {
		return err
	}
	if err := pendingClientStatusQEMU(status); err != nil {
		return err
	}
	for i, proc := range []*os.File{w.client, w.peer} {
		for j, name := range []string{"net", "mnt"} {
			if err := samePendingNamespaceQEMU(w.namespaces[2*i+j], proc, name); err != nil {
				return err
			}
		}
	}
	return nil
}

func pendingClientStatusQEMU(data []byte) error {
	expected := map[string]string{"Uid:": "65534 65534 65534 65534", "Gid:": "65534 65534 65534 65534", "Groups:": "", "CapInh:": "0000000000000000", "CapPrm:": "0000000000000000", "CapEff:": "0000000000000000", "CapBnd:": "0000000000000000", "CapAmb:": "0000000000000000", "NoNewPrivs:": "1"}
	seen := make(map[string]bool)
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if want, ok := expected[fields[0]]; ok {
			if seen[fields[0]] || strings.Join(fields[1:], " ") != want {
				return ErrUnavailable
			}
			seen[fields[0]] = true
		}
	}
	if len(seen) != len(expected) {
		return ErrUnavailable
	}
	return nil
}

// Initial peer comes only from the containing runtime's validated worker proc.
// One bind, no PID/FD selection on later checks, and no descriptor returned.
func (c *PendingClientQEMU) BindConnectionQEMU(ctx context.Context, peer *os.File) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.review || !c.started || c.settled || c.connection != nil || c.process == nil || c.originalProc == nil || len(c.pins) != 3 {
		return ErrReviewRequired
	}
	w := &pendingConnectionQEMU{}
	c.connection = w // Partial construction remains reachable on uncertainty.
	var err error
	w.client, err = retainPendingProcQEMU(c.originalProc)
	if err != nil {
		return c.fail(err)
	}
	w.peer, err = retainPendingProcQEMU(peer)
	if err != nil {
		return c.fail(err)
	}
	w.clientStat = c.originalGeneration
	w.peerStat, err = pendingProcGenerationReadQEMU(w.peer)
	if err != nil || w.clientStat.pid == w.peerStat.pid {
		return c.fail(errors.Join(ErrUnavailable, err))
	}
	for _, proc := range []*os.File{w.client, w.peer} {
		for _, name := range []string{"net", "mnt"} {
			file, err := pendingNamespaceQEMU(proc, name)
			if file != nil {
				w.namespaces = append(w.namespaces, file)
			}
			if err != nil {
				return c.fail(err)
			}
		}
	}
	left, _ := w.namespaces[0].Stat()
	right, _ := w.namespaces[2].Stat()
	if left == nil || right == nil || !os.SameFile(left, right) {
		return c.fail(ErrUnavailable)
	}
	clientMount, _ := w.namespaces[1].Stat()
	peerMount, _ := w.namespaces[3].Stat()
	if clientMount == nil || peerMount == nil || os.SameFile(clientMount, peerMount) {
		return c.fail(ErrUnavailable)
	}
	pair, err := w.observeQEMU(ctx, c)
	if err != nil {
		return c.fail(err)
	}
	w.pair = pair
	return nil
}

func (c *PendingClientQEMU) RecheckConnectionQEMU(ctx context.Context) error {
	if err := c.enter(ctx); err != nil {
		return err
	}
	defer func() { <-c.gate }()
	if c.review || !c.started || c.settled || c.connection == nil {
		return ErrReviewRequired
	}
	pair, err := c.connection.observeQEMU(ctx, c)
	if err != nil || pair != c.connection.pair {
		return c.fail(errors.Join(ErrUnavailable, err))
	}
	return nil
}

func (w *pendingConnectionQEMU) observeQEMU(ctx context.Context, c *PendingClientQEMU) (pendingTCPPairQEMU, error) {
	if err := c.recheckPins(); err != nil {
		return pendingTCPPairQEMU{}, err
	}
	if err := w.recheckProcessesQEMU(c); err != nil {
		return pendingTCPPairQEMU{}, err
	}
	client, err := pendingProcessSocketsQEMU(ctx, w.client)
	if err != nil {
		return pendingTCPPairQEMU{}, err
	}
	peer, err := pendingProcessSocketsQEMU(ctx, w.peer)
	if err != nil {
		return pendingTCPPairQEMU{}, err
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var held, current unix.Stat_t
	if unix.Fstat(int(w.namespaces[0].Fd()), &held) != nil || unix.Stat("/proc/thread-self/ns/net", &current) != nil || held.Dev != current.Dev || held.Ino != current.Ino {
		return pendingTCPPairQEMU{}, ErrUnavailable
	}
	rows, err := pendingTCPKernelQEMU(ctx)
	if err != nil {
		return pendingTCPPairQEMU{}, err
	}
	result, err := matchPendingProcessPairQEMU(ctx, rows, client, peer)
	if err != nil {
		return pendingTCPPairQEMU{}, err
	}
	// Both complete censuses must still contain the selected original socket.
	clientAfter, err := pendingProcessSocketsQEMU(ctx, w.client)
	peerAfter, peerErr := pendingProcessSocketsQEMU(ctx, w.peer)
	contains := func(values []uint32, want uint32) bool {
		for _, value := range values {
			if value == want {
				return true
			}
		}
		return false
	}
	if err != nil || peerErr != nil || !contains(clientAfter, result.client.inode) || !contains(peerAfter, result.server.inode) ||
		unix.Stat("/proc/thread-self/ns/net", &current) != nil || held.Dev != current.Dev || held.Ino != current.Ino {
		return pendingTCPPairQEMU{}, errors.Join(ErrUnavailable, err, peerErr)
	}
	if err := w.recheckProcessesQEMU(c); err != nil {
		return pendingTCPPairQEMU{}, err
	}
	if err := ctx.Err(); err != nil {
		return pendingTCPPairQEMU{}, err
	}
	return result, nil
}

// Fixed IPv4 ESTABLISHED dump only; no filters, setns, destroy or external port.
func pendingTCPKernelQEMU(ctx context.Context) (rows []pendingTCPSocketQEMU, result error) {
	if ctx == nil {
		return nil, ErrInvalid
	}
	bounded, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	if err := bounded.Err(); err != nil {
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
	request := make([]byte, 72)
	binary.NativeEndian.PutUint32(request[:4], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:6], unix.SOCK_DIAG_BY_FAMILY)
	binary.NativeEndian.PutUint16(request[6:8], unix.NLM_F_REQUEST|unix.NLM_F_DUMP)
	binary.NativeEndian.PutUint32(request[8:12], 1)
	request[16], request[17] = unix.AF_INET, unix.IPPROTO_TCP
	binary.NativeEndian.PutUint32(request[20:24], 1<<1)
	for i := 64; i < 72; i++ {
		request[i] = 255
	}
	if err := unix.Sendto(fd, request, unix.MSG_DONTWAIT, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	dump := &pendingTCPDumpQEMU{seq: 1, port: local.Pid}
	buffer := make([]byte, maxPendingTCPDatagramQEMU)
	for !dump.done {
		if err := bounded.Err(); err != nil {
			return nil, err
		}
		n, _, flags, from, err := unix.Recvmsg(fd, buffer, nil, unix.MSG_DONTWAIT)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			if _, err := unix.Poll([]unix.PollFd{{Fd: int32(fd), Events: unix.POLLIN}}, 20); err != nil && !errors.Is(err, unix.EINTR) {
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
	if err := bounded.Err(); err != nil {
		return nil, err
	}
	return dump.result()
}

// Select once from the bounded rows, not a Cartesian repetition of complete
// wire validation. Both process censuses must independently contain the pair.
func matchPendingProcessPairQEMU(ctx context.Context, rows []pendingTCPSocketQEMU, client, peer []uint32) (pendingTCPPairQEMU, error) {
	if ctx == nil || len(client) > 256 || len(peer) > 256 || len(rows) > maxPendingTCPSocketsQEMU {
		return pendingTCPPairQEMU{}, ErrInvalid
	}
	for _, census := range [][]uint32{client, peer} {
		seen := make(map[uint32]bool)
		for _, inode := range census {
			if inode == 0 || seen[inode] {
				return pendingTCPPairQEMU{}, ErrUnavailable
			}
			seen[inode] = true
		}
	}
	contains := func(values []uint32, inode uint32) bool {
		for _, value := range values {
			if value == inode {
				return true
			}
		}
		return false
	}
	service := netip.MustParseAddrPort("127.0.0.1:1445")
	var clientInode, peerInode uint32
	for _, row := range rows {
		if err := ctx.Err(); err != nil {
			return pendingTCPPairQEMU{}, err
		}
		if row.peer == service && row.uid == 65534 && contains(client, row.inode) {
			if clientInode != 0 {
				return pendingTCPPairQEMU{}, ErrUnavailable
			}
			clientInode = row.inode
		}
		if row.local == service && row.uid == 0 && contains(peer, row.inode) {
			if peerInode != 0 {
				return pendingTCPPairQEMU{}, ErrUnavailable
			}
			peerInode = row.inode
		}
	}
	return matchPendingTCPPairQEMU(ctx, rows, clientInode, peerInode)
}

func (w *pendingConnectionQEMU) releaseQEMU() error {
	for len(w.namespaces) > 0 {
		if err := w.namespaces[0].Close(); err != nil {
			return err
		}
		w.namespaces = w.namespaces[1:]
	}
	for _, file := range []**os.File{&w.client, &w.peer} {
		if *file != nil {
			if err := (*file).Close(); err != nil {
				return err
			}
			*file = nil
		}
	}
	return nil
}
