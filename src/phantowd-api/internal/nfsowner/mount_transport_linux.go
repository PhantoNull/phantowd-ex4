// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const mountdPort = 20048

// checkMountTransport reads the current network namespace on the caller's
// locked thread. An absent process requires a free service port. A running
// process must own every listener at that port and only TCP listeners there.
func checkMountTransport(ctx context.Context, pid int) error {
	return checkNFSTransport(ctx, pid, []int{mountdPort})
}

func checkNFSTransport(ctx context.Context, pid int, ports []int) error {
	var owned map[uint64]struct{}
	if pid != 0 {
		var err error
		owned, err = mountProcessSockets(ctx, pid)
		if err != nil {
			return err
		}
	}
	for _, table := range []struct {
		name      string
		ipv6, udp bool
	}{
		{"tcp", false, false}, {"tcp6", true, false},
		{"udp", false, true}, {"udp6", true, true},
	} {
		path := "/proc/thread-self/net/" + table.name
		file, err := os.Open(path)
		if table.ipv6 && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		found, checked := scanNFSTransport(ctx, file, owned, table.udp, ports)
		if err := errors.Join(checked, file.Close()); err != nil {
			return fmt.Errorf("check %s NFS transport: %w", table.name, err)
		}
		if table.name == "tcp" && pid != 0 && !found {
			return ErrState
		}
	}
	return ctx.Err()
}

func mountProcessSockets(ctx context.Context, pid int) (_ map[uint64]struct{}, result error) {
	const maxDescriptors = 1024
	fd, err := unix.Open(fmt.Sprintf("/proc/%d/fd", pid), unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	dir := os.NewFile(uintptr(fd), "mountd-fds")
	defer func() { result = errors.Join(result, dir.Close()) }()
	names, err := dir.Readdirnames(maxDescriptors + 1)
	if err != nil && !errors.Is(err, io.EOF) || len(names) > maxDescriptors {
		return nil, errors.Join(ErrState, err)
	}
	sockets := make(map[uint64]struct{})
	var link [64]byte
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		n, err := unix.Readlinkat(fd, name, link[:])
		if errors.Is(err, unix.ENOENT) {
			continue // A worker can finish with an accepted connection mid-scan.
		}
		if err != nil {
			return nil, err
		}
		encoded, ok := strings.CutPrefix(string(link[:n]), "socket:[")
		if !ok {
			continue
		}
		value, complete := strings.CutSuffix(encoded, "]")
		inode, err := strconv.ParseUint(value, 10, 64)
		if !complete || err != nil || inode == 0 {
			return nil, ErrState
		}
		sockets[inode] = struct{}{}
	}
	return sockets, nil
}

// The pinned Linux profile lists TCP, UDP and IPv6 sockets in proc. TCP
// TIME_WAIT rows do not represent a listener and may have no usable inode.
func scanNFSTransport(ctx context.Context, input io.Reader, owned map[uint64]struct{}, udp bool, ports []int) (bool, error) {
	const maxRows = 8192
	lines := bufio.NewScanner(input)
	lines.Buffer(make([]byte, 1024), 4096)
	if !lines.Scan() || !strings.HasPrefix(strings.TrimSpace(lines.Text()), "sl") {
		return false, errors.Join(ErrState, lines.Err())
	}
	found := false
	for row := 0; lines.Scan(); row++ {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		fields := strings.Fields(lines.Text())
		if row >= maxRows || len(fields) < 4 || len(fields[3]) != 2 {
			return false, ErrState
		}
		if !udp && fields[3] != "0A" {
			continue
		}
		_, encoded, ok := strings.Cut(fields[1], ":")
		port, portErr := strconv.ParseUint(encoded, 16, 16)
		if !ok || len(encoded) != 4 || portErr != nil || len(fields) < 10 {
			return false, ErrState
		}
		inode, err := strconv.ParseUint(fields[9], 10, 64)
		if err != nil {
			return false, ErrState
		}
		_, own := owned[inode]
		switch {
		case slices.Contains(ports, int(port)):
			if udp || !own {
				return false, ErrState
			}
			found = true
		case own:
			return false, ErrState
		}
	}
	return found, lines.Err()
}
