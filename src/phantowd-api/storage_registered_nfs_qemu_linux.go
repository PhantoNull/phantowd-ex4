//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

func withQEMUPeerRegisteredStorage(ctx context.Context, inspect func(*registeredStorage) error) error {
	return mountowner.WithQEMUSupervisedVolumeGrant(ctx, smbFixtureAnchor, func(grant mountowner.LinuxVolumeGrant) (result error) {
		name, err := os.MkdirTemp("/run", "phantowd-peer-registry-")
		if err != nil {
			return err
		}
		defer func() {
			if !constructionreview.Contains(result) {
				result = errors.Join(result, os.RemoveAll(name))
			}
		}()
		dir, err := os.Open(name)
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, dir.Close()) }()
		var filesystem unix.Statfs_t
		if err := unix.Fstatfs(int(dir.Fd()), &filesystem); err != nil || filesystem.Type != unix.TMPFS_MAGIC {
			return errors.Join(errors.New("peer registry requires disposable tmpfs"), err)
		}
		if err := seedQEMUPeerRegistry(ctx, dir, grant); err != nil {
			return err
		}
		approved := registeredStorageGrant{mount: grant, disks: []registeredDiskProof{{
			serial: vpdObservationEvidence("serial", qemuDataSerial),
			wwn:    vpdObservationEvidence("wwn", "naa."+qemuDataWWN),
		}}}
		wrongBacking := approved
		wrongBacking.disks = []registeredDiskProof{{wwn: vpdObservationEvidence("wwn", "naa.500f000000000001")}}
		for _, invalid := range [][]registeredStorageGrant{nil, {wrongBacking}} {
			unexpected, err := admitRegisteredStorage(ctx, dir, invalid)
			if unexpected != nil {
				return errors.Join(errors.New("unapproved registered storage admitted"), unexpected.Close(context.WithoutCancel(ctx)))
			}
			if !errors.Is(err, volumeregistry.ErrObservation) || constructionreview.Contains(err) {
				return errors.Join(errors.New("unapproved registered storage was not cleanly refused"), err)
			}
		}
		storage, err := admitRegisteredStorage(ctx, dir, []registeredStorageGrant{approved})
		if err != nil {
			return err
		}
		defer func() {
			if constructionreview.Contains(result) {
				result = &registeredStorageReviewError{lifetime: storage, cause: result}
				return
			}
			if closeErr := storage.Close(context.WithoutCancel(ctx)); closeErr != nil {
				result = &registeredStorageReviewError{lifetime: storage, cause: errors.Join(result, closeErr)}
			}
		}()
		set, err := storage.Volumes(ctx)
		if err != nil || set == nil {
			return errors.Join(errors.New("registry handoff lost mounted volume"), err)
		}
		lease, active, err := set.Acquire(ctx)
		if err != nil {
			return err
		}
		busyErr := storage.Close(ctx)
		_, verifyErr := lease.Verify()
		releaseErr := lease.Close()
		if !errors.Is(busyErr, mountowner.ErrBusy) || verifyErr != nil || releaseErr != nil {
			return errors.Join(errors.New("registered roster must preserve busy lease"), busyErr, verifyErr, releaseErr)
		}
		if err := qemuPeerCheckRegistryLocked(dir); err != nil {
			return err
		}
		volumes := active.Volumes()
		var stat unix.Statfs_t
		const restrictions = unix.ST_NODEV | unix.ST_NOSUID | unix.ST_NOEXEC
		if len(volumes) != 1 || unix.Statfs(volumes[0].MountPath(), &stat) != nil || stat.Flags&restrictions != restrictions {
			return errors.New("registered bind needs nodev,nosuid,noexec")
		}
		if err := inspect(storage); err != nil {
			return err
		}
		if err := storage.Close(ctx); err != nil {
			return err
		}
		if _, err := set.Observe(); !errors.Is(err, mountowner.ErrUnavailable) {
			return errors.Join(errors.New("closed registered roster remained available"), err)
		}
		writer, err := volumeregistry.OpenWriter(dir)
		if err != nil {
			return err
		}
		return writer.Close()
	})
}

func seedQEMUPeerRegistry(ctx context.Context, dir *os.File, grant mountowner.LinuxVolumeGrant) error {
	doc := volumeregistry.Document{Format: volumeregistry.Format, SchemaVersion: volumeregistry.SchemaVersion,
		Revision: 1, Volumes: []shareconfig.Volume{}}
	writer, err := volumeregistry.OpenWriter(dir)
	if err != nil {
		return err
	}
	if err := errors.Join(writer.CommitPristine(doc), writer.Close()); err != nil {
		return err
	}
	idle, err := admitRegisteredStorage(ctx, dir, nil)
	if err != nil {
		return err
	}
	set, err := idle.Volumes(ctx)
	lockErr := qemuPeerCheckRegistryLocked(dir)
	if closeErr := idle.Close(ctx); set != nil || err != nil || lockErr != nil || closeErr != nil {
		return errors.Join(errors.New("committed empty registry did not remain dormant"), err, lockErr, closeErr)
	}
	writer, err = volumeregistry.OpenWriter(dir)
	if err != nil {
		return err
	}
	doc.Revision++
	doc.Volumes = []shareconfig.Volume{{ID: shareconfig.VolumeID(grant.VolumeID), FilesystemUUID: shareconfig.FilesystemUUID(grant.Expected.FilesystemUUID)}}
	return errors.Join(writer.Commit(1, doc), writer.Close())
}

func qemuPeerCheckRegistryLocked(directory *os.File) error {
	writer, err := volumeregistry.OpenWriter(directory)
	if writer != nil {
		return errors.Join(errors.New("registry writer bypassed retained reader"), writer.Close())
	}
	if !errors.Is(err, revisionstore.ErrBusy) {
		return errors.Join(errors.New("registry reader did not hold the writer lock"), err)
	}
	return nil
}
