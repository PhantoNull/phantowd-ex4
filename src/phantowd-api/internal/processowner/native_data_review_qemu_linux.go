//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import "context"

type NativeDataReviewStopObservationQEMU struct {
	GroupStopped, InputsRetained bool
}

// ObserveNativeDataReviewStopQEMU is a separate read-only witness for the
// single launched data-daemon generation after reviewed, verified teardown.
// Review is mandatory, not ignored. current == nil is set only after the owned
// command has been waited and its whole group verified absent by Stop.
// No signal, Stop/Close retry, pin release, adoption or recovery occurs here;
// open pins prove retention, never fresh input validity or a healthy service.
func (s *PinnedSet) ObserveNativeDataReviewStopQEMU(ctx context.Context) (NativeDataReviewStopObservationQEMU, error) {
	if err := s.enter(ctx); err != nil {
		return NativeDataReviewStopObservationQEMU{}, err
	}
	defer func() { <-s.gate }()
	if len(s.pins) != 15 || len(s.set.members) != 1 || s.set.members[0].name != "native-samba-data" ||
		s.set.generation != 1 || s.set.members[0].owner == nil {
		return NativeDataReviewStopObservationQEMU{}, ErrInvalid
	}
	owner := s.set.members[0].owner
	if !s.set.reviewRequired || s.set.state != StateReviewRequired || !owner.reviewRequired || owner.current != nil {
		return NativeDataReviewStopObservationQEMU{}, ErrReviewRequired
	}
	observed, err := s.set.Observe(ctx)
	if err != ErrReviewRequired || observed.State != StateReviewRequired || observed.Generation != 1 ||
		len(observed.Members) != 1 || observed.Members[0].Name != "native-samba-data" {
		return NativeDataReviewStopObservationQEMU{}, ErrReviewRequired
	}
	member := observed.Members[0].Process
	if member.State != StateReviewRequired || member.Generation != 1 || member.PID != 0 ||
		!owner.reviewRequired || owner.current != nil {
		return NativeDataReviewStopObservationQEMU{}, ErrReviewRequired
	}
	for _, pin := range s.pins {
		if pin == nil {
			return NativeDataReviewStopObservationQEMU{}, ErrReviewRequired
		}
		if _, err := pin.Stat(); err != nil {
			return NativeDataReviewStopObservationQEMU{}, ErrReviewRequired
		}
	}
	if err := ctx.Err(); err != nil {
		return NativeDataReviewStopObservationQEMU{}, err
	}
	return NativeDataReviewStopObservationQEMU{GroupStopped: true, InputsRetained: true}, nil
}
