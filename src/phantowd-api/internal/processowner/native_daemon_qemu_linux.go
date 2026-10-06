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

const nativeDaemonBootstrapMarker = "PHANTOWD_NATIVE_DAEMON_HANDOFF_READY inputs=12 original_config=true original_state=true closed_before_exec=true scope=qemu-only\n"

// NewNativeSambaPinnedSetQEMU fixes one disposable daemon and twelve original
// inputs. The containing runtime separately qualifies their contents/roles and
// revalidates the complete tuple immediately before and after launch.
func NewNativeSambaPinnedSetQEMU(spec MemberSpec, executable *os.File, config [5]*os.File, state [7]*os.File) (_ *PinnedSet, result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	c := spec.Process.RunAs
	if err != nil || string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 ||
		spec.Name != "native-samba" || spec.Process.Executable != "/usr/sbin/phantowd-samba-root-launcher" ||
		len(spec.Process.Args) != 1 || spec.Process.Args[0] != "native-server" || c == nil || c.UID != 0 || c.GID != 0 || len(c.SupplementaryGIDs) != 0 {
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
	var identities [12]unix.Stat_t
	for index := 0; index < 12; index++ {
		var pin *os.File
		if index < 5 {
			pin, err = duplicateNativeConfigurationModeQEMU(config[index], index == 0, index == 4)
		} else {
			pin, err = duplicateSambaStateDirectoryQEMU(state[index-5])
		}
		if err != nil {
			return nil, err
		}
		s.pins = append(s.pins, pin)
		base := 0
		if index >= 5 {
			base = 5
		}
		if unix.Fstat(int(pin.Fd()), &identities[index]) != nil || identities[index].Dev != identities[base].Dev {
			return nil, ErrInvalid
		}
		for prior := 0; prior < index; prior++ {
			if identities[index].Dev == identities[prior].Dev && identities[index].Ino == identities[prior].Ino {
				return nil, ErrInvalid
			}
		}
	}
	inputs := append([]*os.File(nil), s.pins[1:]...)
	program := s.pins[0]
	s.set.members[0].owner.launch = func(spec Spec) (*managedProcess, error) {
		return startPinnedProcessWithInputs(spec, program, inputs)
	}
	return s, nil
}

func (s *PinnedSet) CheckNativeSambaBootstrapQEMU(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if len(s.pins) != 13 || len(s.set.members) != 1 || s.set.members[0].name != "native-samba" {
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
	if ring.dropped != 0 || strings.Count(string(ring.data[:ring.length]), nativeDaemonBootstrapMarker) != 1 {
		return ErrInvalid
	}
	return nil
}
