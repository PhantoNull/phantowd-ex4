// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io/fs"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

var (
	errSMARTCensusIncomplete = errors.New("SMART sysfs census is incomplete")
	errSMARTCensusPrivate    = errors.New("SMART sysfs census is internal")
)

// smartDiskCensus is a private point-in-time observation, not a SMART source
// admission, stable media identity, descriptor lease or command permission.
// Its complete snapshot includes partitions and virtual/stacked nodes even
// though the disk view selects only non-virtual whole leaves. Do not substitute
// the import/mount candidate policy: an in-use disk still needs health monitoring.
type smartDiskCensus struct {
	snapshot storageSnapshot
	disks    []smartDiskObservation
}

type smartDiskObservation struct {
	name         string
	generation   volumeprobe.BlockDeviceGeneration
	serialStatus identityStatus
	wwnStatus    identityStatus
	readOnly     bool
	removable    bool
}

// collectSMARTDiskCensus uses only the existing bounded sysfs collector and its
// complete schema-v2 validator. It never opens /dev, reads /proc mounts, executes
// a tool, issues an ioctl or grants smartcollect.SourceAdmitted. Non-virtual leaf
// topology alone does not prove a transport supports SMART. Missing/ambiguous
// VPD remains explicit; it neither removes a disk nor creates stable identity.
// Context checkpoints do not make synchronous fs.FS reads interruptible.
func collectSMARTDiskCensus(ctx context.Context, sysfs fs.FS) (smartDiskCensus, error) {
	if ctx == nil || sysfs == nil {
		return smartDiskCensus{}, errSMARTCensusIncomplete
	}
	if err := ctx.Err(); err != nil {
		return smartDiskCensus{}, err
	}
	snapshot, err := collectStorage(sysfs)
	if err != nil {
		return smartDiskCensus{}, errSMARTCensusIncomplete
	}
	if err := ctx.Err(); err != nil {
		return smartDiskCensus{}, err
	}
	disks, err := smartDiskObservations(snapshot)
	if err != nil {
		return smartDiskCensus{}, err
	}
	return smartDiskCensus{snapshot: snapshot, disks: disks}, nil
}

func smartDiskObservations(snapshot storageSnapshot) ([]smartDiskObservation, error) {
	if _, err := completeObservedBlockDeviceSet(snapshot); err != nil {
		return nil, errSMARTCensusIncomplete
	}
	disks := make([]smartDiskObservation, 0, len(snapshot.Observations))
	for _, observation := range snapshot.Observations {
		if observation.Kind != "block" || isVirtualBlockTarget(observation.sysfsTarget) || len(observation.lowerBlocks) != 0 {
			continue
		}
		disks = append(disks, smartDiskObservation{
			name: observation.Name,
			generation: volumeprobe.BlockDeviceGeneration{
				Major: observation.Major, Minor: observation.Minor, DiskSequence: observation.diskSequence,
			},
			serialStatus: observation.SerialStatus, wwnStatus: observation.WWNStatus,
			readOnly: observation.ReadOnly, removable: observation.Removable,
		})
	}
	return disks, nil
}

// sameSMARTDiskCensus validates both complete samples and their derived views
// before comparing the entire inventory, including unrelated disks, private VPD
// evidence and topology. A matching tuple alone cannot conceal a changed census.
// This is not an atomic kernel snapshot or a retained device-generation check.
func sameSMARTDiskCensus(first, second smartDiskCensus) bool {
	for _, census := range []smartDiskCensus{first, second} {
		disks, err := smartDiskObservations(census.snapshot)
		if err != nil || census.disks == nil || len(disks) != len(census.disks) {
			return false
		}
		for index, disk := range disks {
			if disk != census.disks[index] {
				return false
			}
		}
	}
	return sameStorageSnapshot(first.snapshot, second.snapshot)
}

func (smartDiskCensus) MarshalJSON() ([]byte, error)      { return nil, errSMARTCensusPrivate }
func (*smartDiskCensus) UnmarshalJSON([]byte) error       { return errSMARTCensusPrivate }
func (smartDiskObservation) MarshalJSON() ([]byte, error) { return nil, errSMARTCensusPrivate }
func (*smartDiskObservation) UnmarshalJSON([]byte) error  { return errSMARTCensusPrivate }
