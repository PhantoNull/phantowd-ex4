//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

var nfsRPCBindRetainedQEMU any

func rpcBindNullQEMU(ctx context.Context) (ready bool, result error) {
	return nfsRPCNullQEMU(ctx, false)
}

func nfsRPCNullQEMU(ctx context.Context, mountd bool) (ready bool, result error) {
	address := "127.0.0.1:111"
	program, version := uint32(100000), uint32(2)
	if mountd {
		address = "127.0.0.1:20048"
		program = 100005
		version = 3
	}
	return nfsFixedNullQEMU(ctx, address, program, version)
}

func nfsFixedNullQEMU(ctx context.Context, address string, program, version uint32) (ready bool, result error) {
	operation, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(operation, "tcp4", address)
	if err != nil {
		if errors.Is(err, unix.ECONNREFUSED) {
			return false, nil
		}
		return false, err
	}
	defer func() { result = errors.Join(result, conn.Close()) }()
	deadline, _ := operation.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return false, err
	}
	words := [...]uint32{0x80000028, 0x50484e01, 0, 2, program, version, 0, 0, 0, 0, 0}
	var request [44]byte
	for index, value := range words {
		binary.BigEndian.PutUint32(request[index*4:], value)
	}
	if n, err := conn.Write(request[:]); err != nil || n != len(request) {
		return false, errors.Join(io.ErrShortWrite, err)
	}
	var response [28]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		return false, err
	}
	if !rpcBindReplyQEMU(response[:]) {
		return false, ErrMismatch
	}
	return true, operation.Err()
}

func nfsRPCBindReadQEMU(path string) (data []byte, result error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	data, err = io.ReadAll(io.LimitReader(file, (64<<10)+1))
	if err != nil || len(data) > 64<<10 {
		return nil, errors.Join(ErrMismatch, err)
	}
	return data, nil
}

// Fixed guest observation only. Connections are not listeners and are not
// used as absence/quiescence evidence. No proc-network API is exposed.
func nfsRPCBindListenerQEMU() (string, error) {
	return nfsRPCListenerQEMU(false)
}

func nfsRPCListenerQEMU(mountd bool) (string, error) {
	found := ""
	wantedPort := "006F"
	if mountd {
		wantedPort = "4E50"
	}
	for _, kind := range []string{"tcp", "tcp6", "udp", "udp6"} {
		data, err := nfsRPCBindReadQEMU("/proc/net/" + kind)
		if err != nil {
			return "", err
		}
		lines := strings.Split(string(data), "\n")
		if len(lines) < 2 || !strings.Contains(lines[0], "local_address") || lines[len(lines)-1] != "" {
			return "", ErrMismatch
		}
		for _, line := range lines[1 : len(lines)-1] {
			fields := strings.Fields(line)
			if len(fields) < 10 || !strings.Contains(fields[1], ":") {
				return "", ErrMismatch
			}
			address, port, _ := strings.Cut(fields[1], ":")
			if port != wantedPort || (strings.HasPrefix(kind, "tcp") && fields[3] != "0A") {
				continue
			}
			inode, err := strconv.ParseUint(fields[9], 10, 64)
			// Socket ownership records the root creator, not the daemon's
			// current UID after setuid. Verify those identities separately.
			// The pinned COTS branch uses getaddrinfo(NULL, AI_PASSIVE):
			// -h restricts UDP, not TCP. The fixture requires the exact
			// wildcard TCP profile with lo the sole active interface.
			if kind != "tcp" || address != "00000000" || fields[7] != "0" || err != nil || inode == 0 || found != "" {
				return "", ErrMismatch
			}
			found = fields[9]
		}
	}
	return found, nil
}

func nfsRPCBindProcessQEMU(pid int, code *nfsCodeLifetimeQEMU, program *os.File, inode string) error {
	return nfsRPCProcessQEMU(pid, code, program, inode, false)
}

func nfsRPCProcessQEMU(pid int, code *nfsCodeLifetimeQEMU, program *os.File, inode string, mountd bool) error {
	root := fmt.Sprintf("/proc/%d", pid)
	status, err := nfsRPCBindReadQEMU(root + "/status")
	if err != nil {
		return err
	}
	expected := map[string]string{"Uid:": "1 1 1 1", "Gid:": "1 1 1 1", "Groups:": "", "CapInh:": "0000000000000000",
		"CapPrm:": "0000000000000000", "CapEff:": "0000000000000000", "CapAmb:": "0000000000000000",
		"CapBnd:": "00000000000004c0", "NoNewPrivs:": "1"}
	if mountd {
		expected["Uid:"] = "0 0 0 0"
		expected["Gid:"] = "0 0 0 0"
		expected["CapBnd:"] = "0000000000000000"
		if code.sourceAccess != nil {
			for _, name := range []string{"CapBnd:", "CapEff:", "CapPrm:"} {
				expected[name] = "0000000000000004"
			}
		}
	}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 0 {
			continue
		}
		if value, ok := expected[fields[0]]; ok {
			if strings.Join(fields[1:], " ") != value {
				return ErrMismatch
			}
			delete(expected, fields[0])
		}
	}
	if len(expected) != 0 {
		return ErrMismatch
	}
	var original, actual unix.Stat_t
	if unix.Fstat(int(program.Fd()), &original) != nil || unix.Stat(root+"/exe", &actual) != nil || original.Dev != actual.Dev || original.Ino != actual.Ino ||
		unix.Stat(root+"/ns/mnt", &actual) != nil || actual.Ino == code.ns.Ino {
		return ErrMismatch
	}
	for path, source := range map[string]*os.File{"code": code.code.root, "etc": code.configuration.contents.root, "run": code.state.root} {
		if unix.Fstat(int(source.Fd()), &original) != nil || unix.Stat(root+"/root/"+path, &actual) != nil || original.Dev != actual.Dev || original.Ino != actual.Ino {
			return ErrMismatch
		}
	}
	fds, err := os.ReadDir(root + "/fd")
	if err != nil || len(fds) > 128 {
		return errors.Join(ErrMismatch, err)
	}
	matches := 0
	for _, fd := range fds {
		target, err := os.Readlink(root + "/fd/" + fd.Name())
		if errors.Is(err, os.ErrNotExist) {
			continue // A transient connection FD proves no absence/completeness.
		}
		if err != nil {
			return err
		}
		if target == "socket:["+inode+"]" {
			matches++
		}
	}
	if matches != 1 {
		return ErrMismatch
	}
	return nil
}

func probeNFSRPCBindQEMU(ctx context.Context, inputs *NFSInputsQEMU) (result error) {
	if !inputs.valid() || nfsCodeGuardQEMU() != nil {
		return ErrInvalid
	}
	s, err := inputs.code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	return probeNFSRPCBindLockedQEMU(ctx, inputs, s)
}

func probeNFSRPCBindLockedQEMU(ctx context.Context, inputs *NFSInputsQEMU, s *nfsCodeLifetimeQEMU) (result error) {
	var daemon *nfsDaemonQEMU
	var bootstrap *os.File
	phase := "inputs"
	defer func() {
		if result != nil {
			s.review, s.cause = true, result
			nfsRPCBindRetainedQEMU = struct {
				inputs    *NFSInputsQEMU
				daemon    *nfsDaemonQEMU
				bootstrap *os.File
				err       error
			}{inputs, daemon, bootstrap, result}
			if !nfsSourceLossExpectedQEMU(s, result) {
				fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_RPCBIND_FAILURE phase=%s\n", phase)
			}
		}
	}()
	if s.review || s.closed || s.configuration == nil || s.state == nil || s.revalidate(ctx) != nil || !errors.Is(inputs.Close(), processowner.ErrBusy) {
		return ErrReviewRequired
	}
	if inode, err := nfsRPCBindListenerQEMU(); err != nil || inode != "" {
		return errors.Join(ErrMismatch, err)
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	bootstrap, err = os.Open("/usr/sbin/phantowd-nfs-table-bootstrap")
	if err != nil {
		return err
	}
	phase = "construct"
	daemon, err = newNFSDaemonQEMU(ctx, s, bootstrap, nil, false)
	if err != nil {
		return err
	}
	if err := s.revalidate(ctx); err != nil {
		return err
	}
	phase = "start"
	if err := daemon.start(ctx); err != nil {
		return err
	} // Original Owner/error retained, never retry start/stop.
	copyDaemon := *daemon
	if copyDaemon.start(ctx) == nil || copyDaemon.check(ctx) == nil || copyDaemon.stop(ctx) == nil || copyDaemon.close() == nil ||
		daemon.start(ctx) == nil || daemon.close() == nil {
		return ErrMismatch
	}
	phase = "ready"
	checkErr := func() error {
		if err := daemon.check(ctx); err != nil {
			return err
		}
		phase = "mountd-composition"
		return probeNFSMountdQEMU(ctx, s, bootstrap, nfsCompanionQEMU{daemon.child, daemon.pid})
	}()
	checkPhase := phase
	if nfsMountdUnsettledQEMU {
		return errors.Join(ErrReviewRequired, checkErr)
	} // Retain BOTH original services until VM disposal.
	phase = "stop"
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopErr := daemon.stop(cleanup)
	cancel()
	if stopErr != nil {
		return errors.Join(ErrReviewRequired, checkErr, stopErr)
	}
	if checkErr != nil {
		phase = checkPhase
		return checkErr
	}
	if !errors.Is(daemon.close(), ErrUnavailable) {
		return ErrMismatch
	}
	if err := daemon.checkStopped(ctx); err != nil {
		return err
	}
	if daemon.stop(ctx) == nil {
		return ErrMismatch
	}
	if err := daemon.close(); err != nil {
		return err
	}
	daemon = nil
	if err := bootstrap.Close(); err != nil {
		return err
	}
	bootstrap = nil
	phase = "closed-inputs"
	if err := s.revalidate(ctx); err != nil {
		return err
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return ErrMismatch
	}
	if err := cleanNFSRPCBindStateQEMU(); err != nil {
		return err
	}
	if s.sourceAccess != nil {
		fmt.Println("PHANTOWD_NFS_SOURCE_RPCBIND_READY original_inputs=true uid_gid=1 capabilities_zero=true listener_pid_bound=true stop_reaped=true fd_balance=true product=false scope=qemu-only")
	} else {
		fmt.Println("PHANTOWD_NFS_RPCBIND_READY original_inputs=true private_view=true uid_gid=1 effective_permitted_zero=true bounding=startup-only listener_pid_bound=true null_rpc=true stop_reaped=true listener_stopped=true fd_balance=true nfsd=true product=false scope=qemu-only")
	}
	return nil
}

// Fixed private RAM leaves, only after independently verified daemon absence.
func cleanNFSRPCBindStateQEMU() error {
	for name, kind := range map[string]uint32{"rpcbind.lock": unix.S_IFREG, "rpcbind.sock": unix.S_IFSOCK} {
		path := filepath.Join(nfsStateViewQEMU, name)
		var st unix.Stat_t
		if unix.Lstat(path, &st) != nil || st.Mode&unix.S_IFMT != kind || st.Uid != 0 || st.Gid != 0 {
			return ErrMismatch
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(nfsStateViewQEMU)
	if err != nil || len(entries) != 1 || entries[0].Name() != "nfs" {
		return errors.Join(ErrMismatch, err)
	}
	return nil
}
