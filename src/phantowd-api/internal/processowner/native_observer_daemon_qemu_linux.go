//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"os"
	"runtime"
	"strings"

	"golang.org/x/sys/unix"
)

const nativeObserverDaemonBootstrapQEMU = "/usr/sbin/phantowd-server-observer-daemon-bootstrap"
const nativeObserverDaemonMarkerQEMU = "PHANTOWD_SERVER_OBSERVER_DAEMON_READY inputs=15 endpoint_fd=3 originals_closed=true caps=00000000000000db nnp=true scope=qemu-only\n"

// NativeObserverDaemonQEMU is a single-use fixture adapter. It is not a
// containing runtime/code/channel lease or a product Samba service.
type NativeObserverDaemonQEMU struct {
	owned     *PinnedSet
	check     func() error
	attempted bool // Protected by the private PinnedSet gate.
}

func (o *NativeObserverDaemonQEMU) Start(ctx context.Context) (SetSnapshot, error) {
	if o == nil || o.owned == nil {
		return SetSnapshot{}, ErrUnavailable
	}
	pins := o.owned
	if err := pins.enter(ctx); err != nil {
		return SetSnapshot{}, err
	}
	defer func() { <-pins.gate }()
	if pins.set.reviewRequired {
		return pins.set.snapshot(), ErrReviewRequired
	}
	if pins.set.state == StateReady {
		return pins.set.snapshot(), ErrAlreadyRunning
	}
	if pins.set.state != StateStopped {
		return pins.set.snapshot(), ErrUnavailable
	}
	if o.attempted {
		o.retainReview()
		return pins.set.snapshot(), ErrReviewRequired
	}
	o.attempted = true
	observed, err := pins.set.Start(ctx)
	if err == nil {
		if o.check == nil {
			err = ErrReviewRequired
		} else {
			err = o.check()
		}
		if err != nil {
			_, stopErr := pins.set.Stop(context.Background())
			err = errors.Join(err, stopErr)
		}
	}
	if err != nil {
		// The generic Owner intentionally classifies readiness failure as
		// NotReady. This dedicated single-use profile must not lose review
		// or retry, even when startup rollback verified process absence.
		o.retainReview()
		return pins.set.snapshot(), errors.Join(ErrReviewRequired, err)
	}
	return observed, nil
}

// Called only under the private PinnedSet gate; no member escapes this adapter.
func (o *NativeObserverDaemonQEMU) retainReview() {
	o.owned.set.reviewRequired = true
	o.owned.set.state = StateReviewRequired
	for index := range o.owned.set.members {
		member := &o.owned.set.members[index]
		member.owner.reviewRequired = true
		member.owner.state = StateReviewRequired
		member.snapshot = member.owner.snapshot()
	}
}

func (o *NativeObserverDaemonQEMU) Stop(ctx context.Context) (SetSnapshot, error) {
	if o == nil || o.owned == nil {
		return SetSnapshot{}, ErrUnavailable
	}
	return o.owned.Stop(ctx)
}

func (o *NativeObserverDaemonQEMU) Close() error {
	if o == nil || o.owned == nil {
		return ErrUnavailable
	}
	return o.owned.Close()
}

func (o *NativeObserverDaemonQEMU) CheckBootstrap(ctx context.Context) error {
	if o == nil || o.owned == nil {
		return ErrUnavailable
	}
	return o.owned.CheckNativeObserverBootstrapQEMU(ctx)
}

// NewNativeObserverDaemonQEMU fixes a separate fixture ABI, not an
// extra-FD option on native/product launchers. The containing caller still must
// qualify complete code/config/state/share authority and keep BOTH original
// channel endpoints until verified whole-service settlement.
func NewNativeObserverDaemonQEMU(spec MemberSpec, executable *os.File,
	config [5]*os.File, state [7]*os.File, roots [2]*os.File, sender *os.File) (owned *NativeObserverDaemonQEMU, result error) {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	credentials := spec.Process.RunAs
	if err != nil || runtime.GOARCH != "arm" || string(model) != "ARM Versatile PB\x00" ||
		os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 ||
		spec.Name != "native-samba-observer" || spec.Process.Executable != nativeObserverDaemonBootstrapQEMU ||
		len(spec.Process.Args) != 0 || credentials == nil || credentials.UID != 0 || credentials.GID != 0 ||
		len(credentials.SupplementaryGIDs) != 0 {
		return nil, ErrInvalid
	}
	set, err := NewPinnedSet([]MemberSpec{spec}, []*os.File{executable})
	if err != nil {
		return nil, err
	}
	defer func() {
		if result != nil {
			if closeErr := set.release(); closeErr != nil {
				// release keeps its terminal error. Never retry an uncertain
				// close or lose the remaining retained input references.
				set.set.reviewRequired = true
				set.set.state = StateReviewRequired
				owned = &NativeObserverDaemonQEMU{owned: set}
				result = errors.Join(ErrReviewRequired, result, closeErr)
			} else {
				owned = nil
			}
		}
	}()
	var identities [12]unix.Stat_t
	for index := range 12 {
		var pin *os.File
		if index < 5 {
			pin, err = duplicateNativeConfigurationModeQEMU(config[index], index == 0, index == 4)
		} else {
			pin, err = duplicateSambaStateDirectoryQEMU(state[index-5])
		}
		if err != nil {
			return nil, err
		}
		set.pins = append(set.pins, pin)
		base := 0
		if index >= 5 {
			base = 5
		}
		if unix.Fstat(int(pin.Fd()), &identities[index]) != nil || identities[index].Dev != identities[base].Dev {
			return nil, ErrInvalid
		}
		for prior := range index {
			if identities[index].Dev == identities[prior].Dev && identities[index].Ino == identities[prior].Ino {
				return nil, ErrInvalid
			}
		}
	}
	var rootIdentities [2]unix.Statx_t
	for index, source := range roots {
		pin, identity, err := duplicateNativeDataRootQEMU(source, index == 0)
		if err != nil {
			return nil, err
		}
		set.pins = append(set.pins, pin)
		rootIdentities[index] = identity
		if index == 1 && (identity.Mnt_id == rootIdentities[0].Mnt_id ||
			(identity.Dev_major == rootIdentities[0].Dev_major && identity.Dev_minor == rootIdentities[0].Dev_minor &&
				identity.Ino == rootIdentities[0].Ino)) {
			return nil, ErrInvalid
		}
	}
	pin, identity, err := duplicateNativeObserverSenderQEMU(sender)
	if pin != nil {
		set.pins = append(set.pins, pin)
	}
	if err != nil {
		if errors.Is(err, ErrReviewRequired) {
			set.releaseErr = err
		}
		return nil, err
	}
	inputs := append([]*os.File(nil), set.pins[1:]...)
	program := set.pins[0]
	ready := set.set.members[0].spec.Ready
	check := func() error {
		observed, err := snapshotNativeObserverSenderQEMU(pin)
		if err != nil || observed != identity {
			return ErrReviewRequired
		}
		return nil
	}
	set.set.members[0].spec.Ready = func(ctx context.Context) (bool, error) {
		if err := check(); err != nil {
			return false, err
		}
		observed, err := ready(ctx)
		if endpointErr := check(); endpointErr != nil {
			return false, errors.Join(err, endpointErr)
		}
		return observed, err
	}
	attempted := false // Serialized by the fixed Set/Owner, never reset.
	set.set.members[0].owner.launch = func(spec Spec) (*managedProcess, error) {
		if attempted {
			return nil, ErrReviewRequired
		}
		attempted = true
		if err := check(); err != nil {
			return nil, err
		}
		return startPinnedProcessWithInputs(spec, program, inputs)
	}
	return &NativeObserverDaemonQEMU{owned: set, check: check}, nil
}

// CheckNativeObserverBootstrapQEMU checks only the fixed diagnostic receipt.
// It does not qualify code/module/worker lifetime or grant producer authority.
func (set *PinnedSet) CheckNativeObserverBootstrapQEMU(ctx context.Context) error {
	if err := set.enter(ctx); err != nil {
		return err
	}
	defer func() { <-set.gate }()
	if len(set.pins) != 16 || len(set.set.members) != 1 || set.set.members[0].name != "native-samba-observer" {
		return ErrInvalid
	}
	owner := set.set.members[0].owner
	owner.diagnosticsMu.RLock()
	ring := owner.lastDiagnostics
	owner.diagnosticsMu.RUnlock()
	if ring == nil {
		return ErrInvalid
	}
	ring.mu.Lock()
	defer ring.mu.Unlock()
	if ring.dropped != 0 || strings.Count(string(ring.data[:ring.length]), nativeObserverDaemonMarkerQEMU) != 1 {
		return ErrInvalid
	}
	return nil
}
