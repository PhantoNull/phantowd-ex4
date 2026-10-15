// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"io/fs"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartdevice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

// openSMARTCensusWitnessSet fixes the existing /dev opener and derives EVERY
// name/generation from a fresh complete private census. It retains metadata
// witnesses only, including in-use whole leaves; it admits no SMART query,
// reads no content and is not called by product startup or any HTTP handler.
// Opening a device is not a standby/no-wake guarantee. Synchronous opens/sysfs
// reads/ioctls remain cooperative, not forcibly interruptible.
func openSMARTCensusWitnessSet(ctx context.Context, sysfs fs.FS) (*smartCensusWitnessSet, error) {
	return openSMARTCensusWitnessSetWith(ctx, sysfs, volumeprobe.OpenObservedBlockSources)
}

// The private constructor seam permits negative fixtures; the default opener
// above is fixed. It is not stored or replaceable by a Check/Close operation.
// Returned source ownership transfers here even on an opener error. No raw
// opener error or partial source set is published. An uncertain close returns
// a non-usable review handle AND error; the caller must retain that handle.
func openSMARTCensusWitnessSetWith(ctx context.Context, sysfs fs.FS, open func([]volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error)) (*smartCensusWitnessSet, error) {
	if ctx == nil || sysfs == nil || open == nil {
		return nil, smartdevice.ErrUnsafe
	}
	baseline, err := collectSMARTDiskCensus(ctx, sysfs)
	if err != nil {
		return nil, smartCensusWitnessError(ctx)
	}
	devices := make([]volumeprobe.ObservedBlockDevice, len(baseline.disks))
	generations := make([]volumeprobe.BlockDeviceGeneration, len(baseline.disks))
	for i, disk := range baseline.disks {
		devices[i] = volumeprobe.ObservedBlockDevice{Name: disk.name, Generation: disk.generation}
		generations[i] = disk.generation
	}
	if len(devices) > volumeprobe.MaxSources {
		return nil, smartdevice.ErrUnsafe // Never truncate a complete census.
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	sources, openErr := open(devices)
	if sources != nil {
		sources = append([]volumeprobe.BlockDeviceSource{}, sources...)
	}
	s := &smartCensusWitnessSet{gate: make(chan struct{}, 1), sysfs: sysfs, baseline: baseline, openedSources: sources}
	s.self = s
	if openErr != nil {
		return refuseSMARTCensusConstruction(s, smartCensusWitnessError(ctx))
	}
	if err := ctx.Err(); err != nil {
		return refuseSMARTCensusConstruction(s, err)
	}
	ordered, err := volumeprobe.OrderCompleteBlockSources(generations, sources)
	if err != nil {
		return refuseSMARTCensusConstruction(s, smartdevice.ErrUnsafe)
	}
	// The original pre-open census remains the baseline. Collecting a fresh
	// baseline here would silently admit topology/VPD drift during opening.
	return finishSMARTCensusWitnessSet(ctx, s, ordered)
}
