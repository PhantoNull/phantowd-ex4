//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math"
	"path"
	"slices"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// MountedVolumeSet owns a fixed, trusted roster of logical-volume mount
// Owners. Its completeness is scoped to that roster; constructing the
// production roster still requires complete trusted storage discovery and
// qualification. The current constructor is used only by internal tests and
// the disposable QEMU fixture.
type MountedVolumeSet struct {
	mu          sync.Mutex
	members     []mountedVolumeMember
	lockOrder   []*Owner
	generation  uint64
	fingerprint [32]byte
}

type mountedVolumeMember struct {
	volumeID string
	owner    *Owner
}

// MountedVolumeSetEvidence represents one all-owner observation taken while
// every Owner in the fixed roster is locked and revalidated. It contains no
// mount authority and is process-local.
type MountedVolumeSetEvidence struct {
	complete    bool
	generation  uint64
	fingerprint [32]byte
	volumes     []MountedVolumeEvidence
}

func (e MountedVolumeSetEvidence) Complete() bool {
	return e.complete && e.generation != 0 && e.fingerprint != [32]byte{} && e.volumes != nil
}

func (e MountedVolumeSetEvidence) Generation() uint64 { return e.generation }

func (e MountedVolumeSetEvidence) Fingerprint() [32]byte { return e.fingerprint }

func (e MountedVolumeSetEvidence) Volumes() []MountedVolumeEvidence {
	return slices.Clone(e.volumes)
}

func (MountedVolumeSetEvidence) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal mounted-volume set evidence is not serializable")
}

func (*MountedVolumeSetEvidence) UnmarshalJSON([]byte) error {
	return errors.New("internal mounted-volume set evidence cannot be deserialized")
}

// newMountedVolumeSet accepts only a non-empty, fixed roster whose target
// anchors map one-to-one to the declared logical IDs. The caller is
// responsible for deriving that roster from a complete trusted scope; it may
// not use a request or caller-provided policy as the authority for membership.
func newMountedVolumeSet(volumeIDs []string, owners []*Owner) (*MountedVolumeSet, error) {
	if volumeIDs == nil || owners == nil || len(volumeIDs) == 0 || len(volumeIDs) != len(owners) ||
		len(volumeIDs) > shareconfig.MaxVolumes {
		return nil, ErrInvalid
	}

	wanted := make(map[string]bool, len(volumeIDs))
	for _, id := range volumeIDs {
		if !validVolumeID(id) || wanted[id] {
			return nil, ErrInvalid
		}
		wanted[id] = true
	}

	members := make([]mountedVolumeMember, 0, len(owners))
	seenOwners := make(map[*Owner]bool, len(owners))
	seenTargets := make(map[string]bool, len(owners))
	for _, owner := range owners {
		if owner == nil || seenOwners[owner] || seenTargets[owner.target] {
			return nil, ErrInvalid
		}
		seenOwners[owner] = true
		seenTargets[owner.target] = true
		matched := ""
		for id := range wanted {
			if owner.target == path.Join(shareconfig.VolumeMountRoot, id) {
				if matched != "" {
					return nil, ErrInvalid
				}
				matched = id
			}
		}
		if matched == "" {
			return nil, ErrInvalid
		}
		members = append(members, mountedVolumeMember{volumeID: matched, owner: owner})
	}
	if len(members) != len(wanted) {
		return nil, ErrInvalid
	}

	slices.SortFunc(members, func(left, right mountedVolumeMember) int {
		return strings.Compare(left.volumeID, right.volumeID)
	})
	lockOrder := make([]*Owner, len(members))
	for index, member := range members {
		lockOrder[index] = member.owner
	}
	slices.SortFunc(lockOrder, func(left, right *Owner) int {
		return strings.Compare(left.target, right.target)
	})
	return &MountedVolumeSet{members: members, lockOrder: lockOrder}, nil
}

// Observe locks every member Owner in canonical target order before reading any
// of them. It returns no partial set: one unavailable or changed mount rejects
// the entire observation. Generation advances whenever any member tuple or
// member Owner generation changes.
func (s *MountedVolumeSet) Observe() (MountedVolumeSetEvidence, error) {
	var evidence MountedVolumeSetEvidence
	err := s.WithEvidence(func(observed MountedVolumeSetEvidence) error {
		evidence = observed
		return nil
	})
	return evidence, err
}

// WithEvidence keeps the complete fixed roster and each member Owner locked
// while inspect consumes the all-or-error observation. It is intended for a
// bounded internal computation that must combine this storage state with
// another Owner snapshot; callbacks must not re-enter this set or any member.
// Multi-owner callers must acquire the mounted-volume set before identity
// Owners, consistently, to avoid lock-order cycles.
func (s *MountedVolumeSet) WithEvidence(inspect func(MountedVolumeSetEvidence) error) error {
	if s == nil || inspect == nil {
		return ErrInvalid
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, owner := range s.lockOrder {
		owner.mu.Lock()
	}
	defer func() {
		for index := len(s.lockOrder) - 1; index >= 0; index-- {
			s.lockOrder[index].mu.Unlock()
		}
	}()

	evidence, err := s.observeLocked()
	if err != nil {
		return err
	}
	return inspect(evidence)
}

func (s *MountedVolumeSet) observeLocked() (MountedVolumeSetEvidence, error) {
	volumes := make([]MountedVolumeEvidence, len(s.members))
	seenUUIDs := make(map[string]bool, len(s.members))
	seenMounts := make(map[uint64]bool, len(s.members))
	seenDevices := make(map[[2]uint32]bool, len(s.members))
	for index, member := range s.members {
		observed, err := member.owner.observeMountedVolumeLocked()
		if err != nil {
			return MountedVolumeSetEvidence{}, err
		}
		device := [2]uint32{observed.deviceMajor, observed.deviceMinor}
		if observed.volumeID != member.volumeID ||
			observed.mountPath != path.Join(shareconfig.VolumeMountRoot, member.volumeID) ||
			observed.compatibility != qualifiedCompatibility || observed.generation == 0 ||
			observed.mountID == 0 || observed.deviceMajor == 0 ||
			seenUUIDs[observed.filesystemUUID] || seenMounts[observed.mountID] || seenDevices[device] {
			return MountedVolumeSetEvidence{}, ErrReview
		}
		seenUUIDs[observed.filesystemUUID] = true
		seenMounts[observed.mountID] = true
		seenDevices[device] = true
		volumes[index] = observed
	}

	fingerprint := fingerprintMountedVolumeSet(volumes)
	if s.generation == 0 {
		s.generation = 1
	} else if fingerprint != s.fingerprint {
		if s.generation == math.MaxUint64 {
			return MountedVolumeSetEvidence{}, ErrReview
		}
		s.generation++
	}
	s.fingerprint = fingerprint
	return MountedVolumeSetEvidence{
		complete: true, generation: s.generation, fingerprint: fingerprint,
		volumes: slices.Clone(volumes),
	}, nil
}

func fingerprintMountedVolumeSet(volumes []MountedVolumeEvidence) [32]byte {
	hash := sha256.New()
	writeUint64 := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		_, _ = hash.Write(encoded[:])
	}
	writeString := func(value string) {
		writeUint64(uint64(len(value)))
		_, _ = hash.Write([]byte(value))
	}
	for _, volume := range volumes {
		writeString(volume.volumeID)
		writeString(volume.filesystemUUID)
		writeString(volume.mountPath)
		writeString(volume.compatibility)
		writeUint64(volume.generation)
		writeUint64(volume.mountID)
		writeUint64(uint64(volume.deviceMajor))
		writeUint64(uint64(volume.deviceMinor))
		if volume.readOnly {
			_, _ = hash.Write([]byte{1})
		} else {
			_, _ = hash.Write([]byte{0})
		}
	}
	var result [32]byte
	copy(result[:], hash.Sum(nil))
	return result
}
