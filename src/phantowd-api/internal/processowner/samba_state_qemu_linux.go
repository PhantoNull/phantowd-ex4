//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

const sambaStateBootstrapMarker = "PHANTOWD_SAMBA_STATE_HANDOFF_READY inputs=7 source_path_masked=true same_objects=true closed_before_exec=true scope=qemu-only\n"

// NewSambaStatePinnedSetQEMU is a fixed disposable bootstrap ABI, not an
// ExtraFiles option for generic processes. Root and the six role directories
// are independently duplicated once; the containing trusted state Owner has
// already qualified their logical roles/identities. No directory getter exists.
func NewSambaStatePinnedSetQEMU(spec MemberSpec, executable *os.File, directories [7]*os.File) (_ *PinnedSet, result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	credentials := spec.Process.RunAs
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 ||
		spec.Name != "samba-state" || spec.Process.Executable != "/usr/sbin/phantowd-samba-root-launcher" ||
		len(spec.Process.Args) != 1 || spec.Process.Args[0] != "owned-state-server" || credentials == nil ||
		credentials.UID != 0 || credentials.GID != 0 || len(credentials.SupplementaryGIDs) != 0 {
		return nil, ErrInvalid
	}
	s, err := NewPinnedSet([]MemberSpec{spec}, []*os.File{executable})
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			result = errors.Join(result, s.release())
		}
	}()
	var identities [7]unix.Stat_t
	for index, source := range directories {
		pin, err := duplicateSambaStateDirectoryQEMU(source)
		if err != nil {
			return nil, err
		}
		s.pins = append(s.pins, pin)
		// Qualify the complete tuple before publication, not only inside the
		// child. Retained independent pins prevent caller close/FD reuse from
		// changing either the comparison or subsequent launch inputs.
		if unix.Fstat(int(pin.Fd()), &identities[index]) != nil || identities[index].Dev != identities[0].Dev {
			return nil, ErrInvalid
		}
		for prior := 0; prior < index; prior++ {
			if identities[index].Ino == identities[prior].Ino {
				return nil, ErrInvalid
			}
		}
	}
	// Fixed captured slice; caller array/file closure cannot retarget launch.
	inputs := append([]*os.File(nil), s.pins[1:]...)
	program := s.pins[0]
	s.set.members[0].owner.launch = func(spec Spec) (*managedProcess, error) {
		return startPinnedProcessWithInputs(spec, program, inputs)
	}
	return s, nil
}

func duplicateSambaStateDirectoryQEMU(source *os.File) (*os.File, error) {
	if source == nil {
		return nil, ErrInvalid
	}
	raw, err := source.SyscallConn()
	if err != nil {
		return nil, ErrInvalid
	}
	fd := -1
	var duplicateErr error
	if err := raw.Control(func(value uintptr) { fd, duplicateErr = unix.FcntlInt(value, unix.F_DUPFD_CLOEXEC, 0) }); err != nil || duplicateErr != nil || fd < 0 {
		return nil, ErrInvalid
	}
	pin := os.NewFile(uintptr(fd), "fixed-samba-state-input")
	flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
	var st unix.Stat_t
	var fs unix.Statfs_t
	if err != nil || flags&unix.O_ACCMODE != unix.O_RDONLY || flags&unix.O_PATH != 0 || flags&unix.O_DIRECTORY == 0 ||
		unix.Fstat(fd, &st) != nil || st.Mode != unix.S_IFDIR|0700 || st.Uid != 0 || st.Gid != 0 ||
		unix.Fstatfs(fd, &fs) != nil || fs.Type != unix.TMPFS_MAGIC || fs.Flags&unix.ST_RDONLY != 0 {
		_ = pin.Close()
		return nil, ErrInvalid
	}
	for _, attribute := range []string{"system.posix_acl_access", "system.posix_acl_default", "security.capability"} {
		if _, err := unix.Fgetxattr(fd, attribute, nil); !errors.Is(err, unix.ENODATA) && !errors.Is(err, unix.ENOTSUP) {
			_ = pin.Close()
			return nil, ErrInvalid
		}
	}
	return pin, nil
}

// CheckSambaStateBootstrapQEMU inspects only bounded private fixture evidence.
// It exposes no diagnostics/descriptor, grants no activation, and is never
// called from readiness (which must not re-enter its own process-set gate).
func (s *PinnedSet) CheckSambaStateBootstrapQEMU(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if len(s.pins) != 8 || len(s.set.members) != 1 || s.set.members[0].name != "samba-state" {
		return ErrInvalid
	}
	owner := s.set.members[0].owner
	owner.diagnosticsMu.RLock()
	ring := owner.lastDiagnostics
	owner.diagnosticsMu.RUnlock()
	if ring == nil {
		return ErrInvalid
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if ring.dropped != 0 {
		return ErrInvalid
	}
	// With no dropped bytes the bounded ring has never wrapped. Read the
	// evidence and truncation state under one lock; never trust a partial tail.
	if strings.Count(string(ring.data[:ring.length]), sambaStateBootstrapMarker) != 1 {
		return ErrInvalid
	}
	return nil
}
