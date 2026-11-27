// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"os"
	"runtime"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const sambaDataPort = 445

// observeSambaTransport admits one owned TCP/IPv4 listener at the selected
// address, rejects all other listeners on TCP/445 or UDP/445, and detects
// connections using the service's local port during drain.
func observeSambaTransport(ctx context.Context, pid int, address netip.Addr) (uint64, bool, error) {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var owned map[uint64]struct{}
	if pid != 0 {
		var err error
		owned, err = ProcessSocketInodes(ctx, pid)
		if err != nil {
			return 0, false, err
		}
	}
	var listener uint64
	drained := true
	for _, table := range []string{"tcp", "tcp6", "udp", "udp6"} {
		file, err := os.Open("/proc/thread-self/net/" + table)
		if strings.HasSuffix(table, "6") && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return 0, false, err
		}
		var fs unix.Statfs_t
		if unix.Fstatfs(int(file.Fd()), &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
			return 0, false, errors.Join(ErrUnavailable, file.Close())
		}
		found, idle, observeErr := scanSambaTransport(ctx, file, table, address, owned)
		if err := errors.Join(observeErr, file.Close()); err != nil {
			return 0, false, err
		}
		if found != 0 {
			listener = found
		}
		drained = drained && idle
	}
	return listener, drained, ctx.Err()
}

// ProcessSocketInodes observes the open socket objects of one pinned child.
func ProcessSocketInodes(ctx context.Context, pid int) (_ map[uint64]struct{}, result error) {
	const limit = 1024
	if pid <= 1 {
		return nil, ErrUnavailable
	}
	fd, err := unix.Open("/proc/"+strconv.Itoa(pid)+"/fd", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	directory := os.NewFile(uintptr(fd), "managed-process-descriptors")
	defer func() { result = errors.Join(result, directory.Close()) }()
	var fs unix.Statfs_t
	if unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.PROC_SUPER_MAGIC {
		return nil, ErrUnavailable
	}
	names, err := directory.Readdirnames(limit + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > limit {
		return nil, errors.Join(ErrUnavailable, err)
	}
	var link [64]byte
	owned := make(map[uint64]struct{})
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := unix.Readlinkat(fd, name, link[:])
		if errors.Is(err, unix.ENOENT) {
			continue
		}
		if err != nil {
			return nil, err
		}
		number, socket := strings.CutPrefix(string(link[:n]), "socket:[")
		if !socket {
			continue
		}
		number, complete := strings.CutSuffix(number, "]")
		inode, err := strconv.ParseUint(number, 10, 64)
		if !complete || err != nil || inode == 0 {
			return nil, ErrUnavailable
		}
		owned[inode] = struct{}{}
	}
	return owned, nil
}

func scanSambaTransport(ctx context.Context, input io.Reader, table string, address netip.Addr,
	owned map[uint64]struct{}) (uint64, bool, error) {
	lines := bufio.NewScanner(input)
	lines.Buffer(make([]byte, 1024), 4096)
	if !lines.Scan() || !strings.HasPrefix(strings.TrimSpace(lines.Text()), "sl") {
		return 0, false, errors.Join(ErrUnavailable, lines.Err())
	}
	var listener uint64
	idle := true
	udp := strings.HasPrefix(table, "udp")
	for row := 0; lines.Scan(); row++ {
		if err := ctx.Err(); err != nil {
			return 0, false, err
		}
		fields := strings.Fields(lines.Text())
		if row >= 8192 || len(fields) < 10 || len(fields[3]) != 2 {
			return 0, false, ErrUnavailable
		}
		local, portString, found := strings.Cut(fields[1], ":")
		port, portErr := strconv.ParseUint(portString, 16, 16)
		inode, inodeErr := strconv.ParseUint(fields[9], 10, 64)
		if !found || len(portString) != 4 || portErr != nil || inodeErr != nil {
			return 0, false, ErrUnavailable
		}
		_, own := owned[inode]
		if udp || fields[3] == "0A" { // TCP_LISTEN
			if port != sambaDataPort && !own {
				continue
			}
			if table != "tcp" || port != sambaDataPort || !own || listener != 0 || !sambaProcAddress(local, address) {
				return 0, false, ErrBusy
			}
			listener = inode
		} else if port == sambaDataPort && fields[3] != "06" { // TCP_TIME_WAIT has no live client.
			idle = false
		}
	}
	return listener, idle, lines.Err()
}

func sambaProcAddress(encoded string, address netip.Addr) bool {
	value, err := strconv.ParseUint(encoded, 16, 32)
	if len(encoded) != 8 || err != nil {
		return false
	}
	var bytes [4]byte
	binary.NativeEndian.PutUint32(bytes[:], uint32(value))
	return netip.AddrFrom4(bytes) == address
}
