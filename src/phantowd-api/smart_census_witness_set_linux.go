// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io/fs"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartdevice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

// This private bridge owns only metadata witnesses. It starts no child, opens
// no device path, reads no contents, and supplies no SMART command admission.
// The trusted constructor caller owns the borrowed source set during Retain;
// the sysfs reader is fixed at construction, never supplied per observation.
type smartCensusWitnessSet struct {
	self             *smartCensusWitnessSet
	gate             chan struct{}
	sysfs            fs.FS
	baseline         smartDiskCensus
	witnesses        []*smartdevice.Witness
	review, closed   bool
	releaseUncertain bool
}

// retainSMARTCensusWitnessSet requires exactly one borrowed read-only block FD
// per whole leaf in a freshly complete census, including in-use leaves. Names
// and raw IDs never escape. It retains independent duplicates all-or-error and
// reconciles the entire inventory around kernel generation rechecks. Missing
// VPD remains observed, not SMART eligibility or persistent identity.
func retainSMARTCensusWitnessSet(ctx context.Context, sysfs fs.FS, sources []volumeprobe.BlockDeviceSource) (*smartCensusWitnessSet, error) {
	if ctx == nil || sysfs == nil {
		return nil, smartdevice.ErrUnsafe
	}
	baseline, err := collectSMARTDiskCensus(ctx, sysfs)
	if err != nil {
		return nil, smartCensusWitnessError(ctx)
	}
	generations := make([]volumeprobe.BlockDeviceGeneration, len(baseline.disks))
	for i, disk := range baseline.disks {
		generations[i] = disk.generation
	}
	ordered, err := volumeprobe.OrderCompleteBlockSources(generations, sources)
	if err != nil {
		return nil, smartdevice.ErrUnsafe
	}
	s := &smartCensusWitnessSet{gate: make(chan struct{}, 1), sysfs: sysfs, baseline: baseline}
	s.self = s
	for _, source := range ordered {
		witness, err := smartdevice.Retain(ctx, source.File, source.Generation)
		if err != nil {
			return nil, errors.Join(smartCensusWitnessError(ctx), s.Close(context.Background()))
		}
		s.witnesses = append(s.witnesses, witness)
	}
	if err := s.Check(ctx); err != nil {
		return nil, errors.Join(err, s.Close(context.Background()))
	}
	return s, nil
}

func smartCensusWitnessError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return smartdevice.ErrUnsafe
}

func (s *smartCensusWitnessSet) enter(ctx context.Context) error {
	if s == nil || s.self != s || s.gate == nil || ctx == nil {
		return smartdevice.ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	select {
	case s.gate <- struct{}{}:
		return nil
	default:
		return smartdevice.ErrBusy
	}
}

// Check is a point-in-time metadata observation, not a media lease, transport
// qualification or sample provenance. Any failed observation keeps review
// sticky, even if the full census later returns to its baseline. Cooperative
// context checks do not make synchronous sysfs reads/kernel ioctls interruptible.
func (s *smartCensusWitnessSet) Check(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.closed {
		return smartdevice.ErrClosed
	}
	if s.review {
		return smartdevice.ErrReview
	}
	for phase := 0; phase < 2; phase++ {
		census, err := collectSMARTDiskCensus(ctx, s.sysfs)
		if err != nil || !sameSMARTDiskCensus(s.baseline, census) {
			s.review = true
			return smartCensusWitnessError(ctx)
		}
		if phase == 0 {
			for _, witness := range s.witnesses {
				if err := witness.Check(ctx); err != nil {
					s.review = true
					return smartCensusWitnessError(ctx)
				}
			}
		}
	}
	return nil
}

// Close releases only owned duplicates, never the caller's sources. No command
// uses these descriptors. Once release starts it attempts all closes regardless
// of caller cancellation; uncertain release stays review and cannot be retried
// into success. It does not signal/stop a future capture or clear review.
func (s *smartCensusWitnessSet) Close(ctx context.Context) error {
	if err := s.enter(ctx); err != nil {
		return err
	}
	defer func() { <-s.gate }()
	if s.releaseUncertain {
		return smartdevice.ErrReview
	}
	if s.closed {
		return nil
	}
	for _, witness := range s.witnesses {
		if err := witness.Close(context.Background()); err != nil {
			s.releaseUncertain, s.review = true, true
		}
	}
	if s.releaseUncertain {
		return smartdevice.ErrReview
	}
	s.closed = true
	s.witnesses, s.sysfs, s.baseline = nil, nil, smartDiskCensus{}
	return nil
}

func (smartCensusWitnessSet) MarshalJSON() ([]byte, error) { return nil, errSMARTCensusPrivate }
func (*smartCensusWitnessSet) UnmarshalJSON([]byte) error  { return errSMARTCensusPrivate }
