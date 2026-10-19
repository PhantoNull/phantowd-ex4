//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import (
	"context"
	"crypto/sha256"
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// ExerciseQEMU checks the same Owner on the guest CPU using memory-only inputs.
// It never opens a file, controls NFSD, mounts data, or grants kernel authority.
func ExerciseQEMU() error {
	ctx := context.Background()
	for _, mode := range []string{"normal", "disabled", "partial-start", "input-drift", "stop-error", "release-error"} {
		candidate, bound, err := syntheticCandidate(mode != "disabled")
		if err != nil {
			return ErrInvalid
		}
		b := &memoryDomain{bound: bound, retained: true, mode: mode}
		o, err := NewQEMU(candidate, b)
		if err != nil {
			return err
		}
		startErr := o.Start(ctx)
		if mode == "partial-start" {
			if !errors.Is(startErr, ErrReviewRequired) {
				return ErrInvalid
			}
		} else {
			if startErr != nil || o.Check(ctx) != nil {
				return ErrInvalid
			}
			if mode == "input-drift" {
				b.bound.StorageGeneration++
				if !errors.Is(o.Check(ctx), ErrReviewRequired) {
					return ErrInvalid
				}
			} else if mode == "stop-error" || mode == "release-error" {
				if !errors.Is(o.Close(ctx), ErrReviewRequired) {
					return ErrInvalid
				}
			} else {
				if o.Close(ctx) != nil || b.retained || b.running || b.starts != boolCount(mode != "disabled") || b.stops != b.starts || b.releases != 1 {
					return ErrInvalid
				}
				continue
			}
		}
		state, err := o.Observe()
		if err != nil || state != ReviewRequired || !b.retained || b.running || b.stops != 1 {
			return ErrInvalid
		}
		starts, stops, releases := b.starts, b.stops, b.releases
		b.mode = "normal"
		for _, operation := range []func(context.Context) error{o.Start, o.Check, o.Stop, o.Close} {
			if !errors.Is(operation(ctx), ErrReviewRequired) {
				return ErrInvalid
			}
		}
		if b.starts != starts || b.stops != stops || b.releases != releases || !b.retained {
			return ErrInvalid
		}
	}
	return nil
}

func boolCount(v bool) int {
	if v {
		return 1
	}
	return 0
}

type memoryDomain struct {
	bound                   fileserviceplan.Freshness
	retained, running       bool
	starts, stops, releases int
	mode                    string
}

func (b *memoryDomain) CheckInputs(_ context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	if !b.retained || !candidate.FreshAgainst(b.bound) {
		return ErrInvalid
	}
	return nil
}
func (b *memoryDomain) VerifyStopped(context.Context) error {
	if b.running {
		return ErrInvalid
	}
	return nil
}
func (b *memoryDomain) Start(context.Context) error {
	b.starts++
	b.running = true
	if b.mode == "partial-start" {
		return ErrInvalid
	}
	return nil
}
func (b *memoryDomain) VerifyReady(context.Context) error {
	if !b.running {
		return ErrInvalid
	}
	return nil
}
func (b *memoryDomain) Stop(context.Context) error {
	b.stops++
	b.running = false
	if b.mode == "stop-error" {
		return ErrInvalid
	}
	return nil
}
func (b *memoryDomain) Release(context.Context) error {
	b.releases++
	if b.running || !b.retained || b.mode == "release-error" {
		return ErrInvalid
	}
	b.retained = false
	return nil
}

func syntheticCandidate(enabled bool) (fileserviceplan.NFSv3Candidate, fileserviceplan.Freshness, error) {
	registry, err := serviceaccounts.New(1000, 2000)
	if err != nil {
		return fileserviceplan.NFSv3Candidate{}, fileserviceplan.Freshness{}, ErrInvalid
	}
	const uuid = "11111111-2222-3333-4444-555555555555"
	shares := shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: "bulk", FilesystemUUID: uuid}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}}
	nfs := nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}}
	if enabled {
		nfs.Exports = []nfsconfig.Export{{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: "bulk", RelativePath: "books",
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}
	}
	plan, err := fileserviceplan.Build(fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1, Shares: shares, NFS: nfs}, 0,
		fileserviceplan.IdentitySnapshot{Complete: true, Generation: 1, Fingerprint: sha256.Sum256([]byte("memory-only-nfs-owner-fixture")), Registry: registry, UnixUIDs: []uint32{1000}, UnixGIDs: []uint32{1000}, Samba: []fileserviceplan.SambaIdentity{}},
		fileserviceplan.StorageSnapshot{Complete: true, Generation: 1, Volumes: []fileserviceplan.ObservedVolume{{VolumeID: "bulk", FilesystemUUID: uuid, MountPath: shareconfig.VolumeMountRoot + "/bulk", Compatibility: fileserviceplan.CompatibilityQualified, MountID: 73, DeviceMajor: 9, DeviceMinor: 1}}})
	if err != nil {
		return fileserviceplan.NFSv3Candidate{}, fileserviceplan.Freshness{}, ErrInvalid
	}
	candidate, err := plan.NFSv3TCPCandidate()
	return candidate, plan.Freshness(), err
}
