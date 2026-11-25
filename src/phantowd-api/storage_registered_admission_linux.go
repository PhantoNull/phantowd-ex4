// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
)

// registeredStorageGrant describes a mount independently approved by the
// platform supervisor. The registry cannot authorize a backing or a mount.
type registeredStorageGrant struct {
	mount  mountowner.LinuxVolumeGrant
	disks  []registeredDiskProof
	arrays []registeredMDProof
}

type registeredDiskProof struct {
	serial, wwn [32]byte
}

type registeredMDProof struct {
	uuid, level string
}

// registeredStorage retains the protected registry reader for the entire
// mounted-roster lifetime. A validated empty registry has a dormant lifetime.
type registeredStorage struct {
	mu       sync.Mutex
	reader   *volumeregistry.Reader
	snapshot volumeregistry.Snapshot
	roster   *mountowner.LinuxMountedRoster
	closed   bool
	review   error
}

// admitRegisteredStorage reconciles an independently approved complete roster
// with the registry and the fixed current kernel namespace. It mounts only
// already-mounted roots; the supervisor serializes changes to the namespace.
func admitRegisteredStorage(ctx context.Context, directory *os.File, approved []registeredStorageGrant) (*registeredStorage, error) {
	if ctx == nil || ctx.Err() != nil {
		return nil, volumeregistry.ErrObservation
	}
	reader, err := volumeregistry.Open(directory)
	if err != nil {
		return nil, err
	}
	lifetime := &registeredStorage{reader: reader}
	fail := func(cause error) (*registeredStorage, error) {
		result, retain := constructionreview.Rollback(cause, func() error { return lifetime.Close(context.WithoutCancel(ctx)) })
		if retain {
			return nil, &registeredStorageReviewError{lifetime: lifetime, cause: result}
		}
		return nil, result
	}
	lifetime.snapshot, err = reader.Read(ctx)
	if err != nil {
		return fail(err)
	}
	sysfs, proc := os.DirFS("/sys"), os.DirFS("/proc")
	before, err := collectTrustedMountedExtCensus(ctx, sysfs, proc)
	if err != nil {
		return fail(fmt.Errorf("observe original storage scope: %w", err))
	}
	grants, err := matchRegisteredStorage(lifetime.snapshot, before, approved)
	if err != nil {
		return fail(fmt.Errorf("reconcile registry and storage approval: %w", err))
	}
	var evidence []mountowner.MountedVolumeEvidence
	if len(grants) != 0 {
		lifetime.roster, err = mountowner.AdmitLinuxMountedRoster(ctx, grants)
		if err != nil {
			return fail(err)
		}
		observed, err := lifetime.roster.Volumes().Observe()
		if err != nil {
			return fail(err)
		}
		evidence = observed.Volumes()
	}
	after, err := collectTrustedMountedExtCensus(ctx, sysfs, proc)
	if err != nil || !registeredStorageCensusUnchanged(before, after, evidence) {
		return fail(fmt.Errorf("recheck storage scope after bind: %w", volumeregistry.ErrObservation))
	}
	if _, err := lifetime.Volumes(ctx); err != nil {
		return fail(err)
	}
	return lifetime, nil
}

func matchRegisteredStorage(snapshot volumeregistry.Snapshot, census trustedMountedExtCensus, approved []registeredStorageGrant) ([]mountowner.LinuxVolumeGrant, error) {
	review, err := reviewRegisteredMountedVolumes(snapshot, census)
	if err != nil || len(review.volumes) != len(approved) {
		return nil, volumeregistry.ErrObservation
	}
	byID := make(map[string]registeredStorageGrant, len(approved))
	for _, grant := range approved {
		byID[grant.mount.VolumeID] = grant
	}
	claims, err := snapshot.Claims()
	if err != nil {
		return nil, err
	}
	for _, claim := range claims.Volumes {
		grant, exists := byID[string(claim.ID)]
		if !exists || grant.mount.Expected.FilesystemUUID != string(claim.FilesystemUUID) || grant.mount.Source == nil {
			return nil, volumeregistry.ErrObservation
		}
	}
	byAnchor := make(map[string]mountedStorageIdentity, len(census.identities))
	for _, identity := range census.identities {
		byAnchor[identity.anchor] = identity
	}
	grants := make([]mountowner.LinuxVolumeGrant, 0, len(approved))
	for _, volume := range review.volumes {
		grant := byID[string(volume.volumeID)]
		identity := byAnchor[grant.mount.SourcePath]
		expected := grant.mount.Expected
		if volume.objectCount != 1 || volume.aliasCount != 1 || volume.scopedDiskEvidenceUnresolved ||
			identity.filesystemUUIDConflict || identity.filesystemUUID != expected.FilesystemUUID ||
			identity.mountID != expected.MountID || identity.sourceMajor != expected.DeviceMajor ||
			identity.sourceMinor != expected.DeviceMinor || !matchesRegisteredBacking(identity, grant) {
			return nil, volumeregistry.ErrObservation
		}
		grants = append(grants, grant.mount)
	}
	return grants, nil
}

func matchesRegisteredBacking(identity mountedStorageIdentity, grant registeredStorageGrant) bool {
	if len(identity.physicalDisks) == 0 || len(identity.physicalDisks) != len(grant.disks) || len(identity.arrays) != len(grant.arrays) {
		return false
	}
	zero := [32]byte{}
	used := make([]bool, len(identity.physicalDisks))
	for _, proof := range grant.disks {
		if proof.serial == zero && proof.wwn == zero {
			return false
		}
		matched := false
		for i, disk := range identity.physicalDisks {
			if used[i] ||
				(proof.serial != zero && (disk.serialStatus != identityPresent || disk.serialEvidence != proof.serial)) ||
				(proof.wwn != zero && (disk.wwnStatus != identityPresent || disk.wwnEvidence != proof.wwn)) {
				continue
			}
			used[i], matched = true, true
			break
		}
		if !matched {
			return false
		}
	}
	arrays := make(map[registeredMDProof]bool, len(identity.arrays))
	for _, array := range identity.arrays {
		arrays[registeredMDProof{uuid: array.arrayUUID, level: array.level}] = true
	}
	for _, array := range grant.arrays {
		if !arrays[array] {
			return false
		}
		delete(arrays, array)
	}
	return len(arrays) == 0
}

// The only allowed additions to the original census are the exact mounts the
// roster just verified. Strip those from copies, then compare the whole scope.
func registeredStorageCensusUnchanged(before, after trustedMountedExtCensus, evidence []mountowner.MountedVolumeEvidence) bool {
	if validateMountedExtCensus(after) != nil ||
		!sameStorageSnapshot(before.storage, after.storage) || !sameMountedCensusArrays(before.arrays, after.arrays) {
		return false
	}
	bound := make(map[string]mountowner.MountedVolumeEvidence, len(evidence))
	for _, volume := range evidence {
		bound[volume.MountPath()] = volume
	}
	mounts := after.mounts
	mounts.Mounts = make([]mountObservation, 0, len(before.mounts.Mounts))
	for _, observed := range after.mounts.Mounts {
		volume, isBind := bound[observed.MountPoint]
		if !isBind {
			mounts.Mounts = append(mounts.Mounts, observed)
		} else if observed.ReadOnly != volume.ReadOnly() {
			return false
		}
	}
	mounts.MountCount = len(mounts.Mounts)
	roots := after.roots
	roots.Mounts = make([]mountguard.MountedIdentity, 0, len(before.roots.Mounts))
	for _, observed := range after.roots.Mounts {
		volume, isBind := bound[observed.Anchor]
		if !isBind {
			roots.Mounts = append(roots.Mounts, observed)
			continue
		}
		if observed.MountID != volume.MountID() || observed.FilesystemUUID != volume.FilesystemUUID() ||
			observed.DeviceMajor != volume.DeviceMajor() || observed.DeviceMinor != volume.DeviceMinor() {
			return false
		}
		delete(bound, observed.Anchor)
	}
	return len(bound) == 0 && sameMountSnapshot(before.mounts, mounts) && sameMountedCensusRoots(before.roots, roots)
}

// Volumes checks authority at service handoff. A nil set with no error is an
// explicitly empty registry. Clients stop dependent lifetimes before Close.
func (s *registeredStorage) Volumes(ctx context.Context) (*mountowner.MountedVolumeSet, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.review != nil || s.reader.Recheck(ctx, s.snapshot) != nil {
		return nil, volumeregistry.ErrObservation
	}
	if s.roster == nil {
		return nil, nil
	}
	set := s.roster.Volumes()
	if _, err := set.Observe(); err != nil {
		return nil, err
	}
	return set, nil
}

func (s *registeredStorage) Close(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.review != nil {
		return s.review
	}
	if s.roster != nil {
		if err := s.roster.Close(ctx); err != nil {
			if constructionreview.Contains(err) {
				s.review = err
			}
			return err
		}
	}
	s.closed = true
	if err := s.reader.Close(); err != nil {
		s.review = &registeredStorageReviewError{lifetime: s, cause: err}
	}
	return s.review
}

type registeredStorageReviewError struct {
	constructionreview.Marker
	lifetime *registeredStorage
	cause    error
}

func (r *registeredStorageReviewError) Error() string {
	return fmt.Sprintf("registered storage requires review: %s", r.cause)
}

func (r *registeredStorageReviewError) Unwrap() error { return r.cause }
