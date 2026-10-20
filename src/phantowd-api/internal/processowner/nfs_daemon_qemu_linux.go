//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const nfsRPCBindHandoffQEMU = "PHANTOWD_NFS_RPCBIND_HANDOFF private_view=true initial_caps=bind-setuid-setgid active_interfaces=lo fixed_rpcbind=true\n"

// NewNFSRPCBindPinnedQEMU is a fixed foreground daemon fixture, not a generic
// descriptor/privilege extension or product service constructor. The trusted
// containing lifetime must hold/revalidate the SAME original inputs through
// verified whole-group settlement before releasing this set or its inputs.
func NewNFSRPCBindPinnedQEMU(spec MemberSpec, bootstrap *os.File, objects [4]*os.File) (_ *PinnedSet, result error) {
	c := spec.Process.RunAs
	if !nfsRuntimeFixtureGuardQEMU() || spec.Name != "nfs-rpcbind" ||
		spec.Process.Executable != "/usr/sbin/phantowd-nfs-table-bootstrap" || len(spec.Process.Args) != 1 || spec.Process.Args[0] != "rpcbind-v1" ||
		c == nil || c.UID != 0 || c.GID != 0 || len(c.SupplementaryGIDs) != 0 ||
		spec.Process.ReadyTimeout != 5*time.Second || spec.Process.ProbeInterval != 20*time.Millisecond || spec.Process.StopTimeout != time.Second {
		return nil, ErrInvalid
	}
	return newNFSFixedDaemonQEMU(spec, bootstrap, objects, nil)
}

func newNFSFixedDaemonQEMU(spec MemberSpec, bootstrap *os.File, objects [4]*os.File, channels []*os.File) (_ *PinnedSet, result error) {
	return newNFSFixedDaemonInputsQEMU(spec, bootstrap, objects, channels, func(file *os.File, index int) bool { return nfsKernelInputQEMU(file, index == 3) })
}

func newNFSFixedDaemonInputsQEMU(spec MemberSpec, bootstrap *os.File, objects [4]*os.File, channels []*os.File, valid func(*os.File, int) bool) (_ *PinnedSet, result error) {
	s, err := NewPinnedSet([]MemberSpec{spec}, []*os.File{bootstrap})
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = s.constructionRollback(result)
		}
	}()
	for index, source := range objects {
		if source == nil {
			return nil, ErrInvalid
		}
		raw, err := source.SyscallConn()
		if err != nil {
			return nil, ErrInvalid
		}
		fd := -1
		var dupErr error
		if err := raw.Control(func(value uintptr) { fd, dupErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || dupErr != nil || fd < 0 {
			return nil, ErrInvalid
		}
		pin := os.NewFile(uintptr(fd), "fixed-nfs-rpcbind-input")
		s.pins = append(s.pins, pin)
		if !nfsTableObjectQEMU(pin, index) {
			return nil, ErrInvalid
		}
	}
	for index, source := range channels {
		pin, err := duplicateNFSKernelInputQEMU(source)
		if err != nil {
			return nil, err
		}
		s.pins = append(s.pins, pin)
		if !valid(pin, index) {
			return nil, ErrInvalid
		}
	}
	program := s.pins[0]
	inputs := append([]*os.File(nil), s.pins[1:]...)
	s.set.members[0].owner.launch = func(spec Spec) (*managedProcess, error) {
		return startPinnedProcessWithInputs(spec, program, inputs)
	}
	return s, nil
}

// Called only after Start returns; a readiness callback must not re-enter its
// owning set. A handoff alone is not daemon/socket/credential readiness proof.
func (s *PinnedSet) CheckNFSRPCBindHandoffQEMU(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if len(s.pins) != 5 || len(s.set.members) != 1 || s.set.members[0].name != "nfs-rpcbind" ||
		string(s.set.members[0].owner.Diagnostics()) != nfsRPCBindHandoffQEMU {
		return ErrInvalid
	}
	return nil
}
