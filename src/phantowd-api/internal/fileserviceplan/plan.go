// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package fileserviceplan compiles desired SMB/NFS policy against one complete
// trusted identity and mounted-volume observation. A Plan is an in-memory,
// internal candidate only: it cannot persist or activate a service.
package fileserviceplan

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"path"
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const (
	CompatibilityQualified   = "qualified"
	CompatibilityUnqualified = "unqualified"
	MaxObservedVolumes       = shareconfig.MaxVolumes
	MaxUnixIdentities        = 4096
)

var (
	ErrInvalidPolicy   = errors.New("invalid desired file-service policy")
	ErrNotReady        = errors.New("file-service activation evidence is incomplete")
	ErrInvalidEvidence = errors.New("file-service activation evidence is inconsistent")
)

// ObservedVolume is an internal snapshot produced by the storage lifecycle
// owner, never by HTTP. CompatibilityQualified means an exact layout policy
// has accepted this filesystem. MountPath must be the fixed logical anchor;
// device numbers and mount ID are transient and cannot be persisted as identity.
type ObservedVolume struct {
	VolumeID       shareconfig.VolumeID
	FilesystemUUID shareconfig.FilesystemUUID
	MountPath      string
	Compatibility  string
	MountID        uint64
	DeviceMajor    uint32
	DeviceMinor    uint32
	ReadOnly       bool
}

// StorageSnapshot is complete only when the trusted owner has observed every
// mounted logical volume in its scope and checked identity/compatibility. The
// generation changes whenever any binding or relevant mount state changes.
type StorageSnapshot struct {
	Complete         bool
	Generation       uint64
	OwnerFingerprint [32]byte
	Volumes          []ObservedVolume
}

// SambaIdentity pairs one Owner journal with a fresh redacted passdb
// observation. The observation contains no credential/hash material.
type SambaIdentity struct {
	Journal     smbprovision.Journal
	Observation smbprovision.Observation
}

// IdentitySnapshot is an all-or-error view from the identity owner plus the
// complete local UID/GID census used for NFS squash mappings. Generation is
// the desired-registry revision; Fingerprint also binds native/Samba journals,
// local reservations and current passdb observations. It is not built from
// desired JSON or supplied by an HTTP client.
type IdentitySnapshot struct {
	Complete      bool
	Generation    uint64
	Fingerprint   [32]byte
	Registry      serviceaccounts.Registry
	UnixUIDs      []uint32
	UnixGIDs      []uint32
	Samba         []SambaIdentity
	KerberosReady bool
}

// Freshness binds a candidate to the current policy, active service revision,
// identity generation plus complete evidence fingerprint, and complete
// volume/mount observation.
type Freshness struct {
	PolicyRevision      uint64
	ActiveRevision      uint64
	IdentityGeneration  uint64
	IdentityFingerprint [32]byte
	StorageGeneration   uint64
	StorageFingerprint  [32]byte
}

func (Freshness) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal file-service freshness evidence is not serializable")
}

func (*Freshness) UnmarshalJSON([]byte) error {
	return errors.New("internal file-service freshness evidence cannot be deserialized")
}

type VolumeBinding struct {
	VolumeID       shareconfig.VolumeID
	FilesystemUUID shareconfig.FilesystemUUID
	MountPath      string
	MountID        uint64
	DeviceMajor    uint32
	DeviceMinor    uint32
	ReadOnly       bool
}

// Plan deliberately has no exported fields and cannot be serialized. The
// eventual service owner may consume its rendered candidates internally only
// after M3.4/M4.2/M4.4 mount, lease and lifecycle contracts are implemented.
// There is intentionally no Apply method or activation capability here.
type Plan struct {
	schemaVersion       int
	freshness           Freshness
	scope               string
	activationAvailable bool
	applied             bool
	runtimeValidated    bool
	volumes             []VolumeBinding
	sambaConfig         string
	sambaPasswd         string
	sambaGroup          string
	sambaNSS            string
	nfsConfig           string
	requirements        []string
}

// Build validates a combined desired revision against complete, current
// identity and storage snapshots, then renders deterministic candidate daemon
// text. activeRevision is the revision presently considered active (zero means
// none). A plan never starts/stops services or writes a configuration file.
func Build(config fileservice.Config, activeRevision uint64, identities IdentitySnapshot, storage StorageSnapshot) (Plan, error) {
	if config.Validate() != nil {
		return Plan{}, ErrInvalidPolicy
	}
	preview, err := fileservice.Build(config.Shares, config.NFS)
	if err != nil {
		return Plan{}, ErrInvalidPolicy
	}
	if err := validateIdentitySnapshot(identities); err != nil {
		return Plan{}, err
	}
	if err := validateStorageSnapshot(storage, config.Shares); err != nil {
		return Plan{}, err
	}
	if err := validateSMBAccounts(config.Shares, identities); err != nil {
		return Plan{}, err
	}
	passwd, group, nss, err := renderSambaNSS(config.Shares, identities.Registry)
	if err != nil {
		return Plan{}, err
	}
	if err := validateNFSIdentities(config.NFS, identities); err != nil {
		return Plan{}, err
	}
	if preview.NFS.RequiresKerberos && !identities.KerberosReady {
		return Plan{}, ErrNotReady
	}

	used, writes := referencedVolumes(config)
	observed := make(map[shareconfig.VolumeID]ObservedVolume, len(storage.Volumes))
	for _, volume := range storage.Volumes {
		observed[volume.VolumeID] = volume
	}
	bindings := make([]VolumeBinding, 0, len(used))
	for id := range used {
		volume, ok := observed[id]
		if !ok || volume.Compatibility != CompatibilityQualified {
			return Plan{}, ErrNotReady
		}
		expected, ok := desiredVolume(config.Shares, id)
		if !ok || volume.FilesystemUUID != expected.FilesystemUUID {
			return Plan{}, ErrInvalidEvidence
		}
		if writes[id] && volume.ReadOnly {
			return Plan{}, ErrNotReady
		}
		bindings = append(bindings, VolumeBinding{
			VolumeID: volume.VolumeID, FilesystemUUID: volume.FilesystemUUID, MountPath: volume.MountPath,
			MountID: volume.MountID, DeviceMajor: volume.DeviceMajor, DeviceMinor: volume.DeviceMinor, ReadOnly: volume.ReadOnly,
		})
	}
	slices.SortFunc(bindings, func(a, b VolumeBinding) int { return strings.Compare(string(a.VolumeID), string(b.VolumeID)) })

	return Plan{
		schemaVersion: 1,
		freshness: Freshness{
			PolicyRevision: config.Revision, ActiveRevision: activeRevision,
			IdentityGeneration: identities.Generation, IdentityFingerprint: identities.Fingerprint,
			StorageGeneration: storage.Generation, StorageFingerprint: fingerprintStorageSnapshot(storage),
		},
		scope: "candidate-only", activationAvailable: false, applied: false, runtimeValidated: false,
		volumes: bindings, sambaConfig: preview.Samba.Sections, nfsConfig: preview.NFS.Table,
		sambaPasswd: passwd, sambaGroup: group, sambaNSS: nss,
		requirements: slices.Clone(preview.Requirements),
	}, nil
}

// FreshAgainst rejects a plan after any input generation or policy revision
// changes. The service owner must call it immediately before any later apply
// operation; it is not itself an atomic lease or a substitute for M4.4.
func (p Plan) FreshAgainst(current Freshness) bool {
	return p.scope == "candidate-only" && p.freshness == current
}

// Freshness returns the exact revision/evidence tuple bound to this candidate.
// The service owner must build a new candidate from freshly collected inputs
// and compare its tuple before any future transactional handoff.
func (p Plan) Freshness() Freshness { return p.freshness }

func fingerprintStorageSnapshot(snapshot StorageSnapshot) [32]byte {
	h := sha256.New()
	writeUint64 := func(value uint64) {
		var encoded [8]byte
		binary.BigEndian.PutUint64(encoded[:], value)
		_, _ = h.Write(encoded[:])
	}
	writeString := func(value string) {
		writeUint64(uint64(len(value)))
		_, _ = h.Write([]byte(value))
	}
	writeUint64(uint64(snapshot.Generation))
	_, _ = h.Write(snapshot.OwnerFingerprint[:])
	if snapshot.Complete {
		_, _ = h.Write([]byte{1})
	} else {
		_, _ = h.Write([]byte{0})
	}
	volumes := slices.Clone(snapshot.Volumes)
	slices.SortFunc(volumes, func(left, right ObservedVolume) int {
		return strings.Compare(string(left.VolumeID), string(right.VolumeID))
	})
	writeUint64(uint64(len(volumes)))
	for _, volume := range volumes {
		writeString(string(volume.VolumeID))
		writeString(string(volume.FilesystemUUID))
		writeString(volume.MountPath)
		writeString(volume.Compatibility)
		writeUint64(volume.MountID)
		writeUint64(uint64(volume.DeviceMajor))
		writeUint64(uint64(volume.DeviceMinor))
		if volume.ReadOnly {
			_, _ = h.Write([]byte{1})
		} else {
			_, _ = h.Write([]byte{0})
		}
	}
	var fingerprint [32]byte
	copy(fingerprint[:], h.Sum(nil))
	return fingerprint
}

// RenderedCandidates returns copies of the deterministic config strings. The
// caller must still run native parsers and preserve the live configuration on
// error; the returned text is not installed or validated by this package.
func (p Plan) RenderedCandidates() (samba, nfs string) { return p.sambaConfig, p.nfsConfig }

// Requirements returns an independent copy of unresolved runtime/service gates.
func (p Plan) Requirements() []string { return slices.Clone(p.requirements) }

// RequiredVolumes returns an independent copy of the transient volume bindings.
func (p Plan) RequiredVolumes() []VolumeBinding { return slices.Clone(p.volumes) }

// MarshalJSON is deliberately refused: mount paths, filesystem IDs and transient
// device tuples must remain internal, non-persisted observations.
func (Plan) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal file-service plan is not serializable")
}

// UnmarshalJSON prevents external or persisted JSON from manufacturing a plan
// with incomplete evidence. Plans must be rebuilt from trusted owner snapshots.
func (*Plan) UnmarshalJSON([]byte) error {
	return errors.New("internal file-service plan cannot be deserialized")
}

// IdentitySnapshot contains host-local account reservations and Samba IDs.
// StorageSnapshot contains transient mount/device bindings. Keep both within
// the trusted process boundary instead of allowing accidental API/log output.
func (IdentitySnapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal file-service identity evidence is not serializable")
}

func (*IdentitySnapshot) UnmarshalJSON([]byte) error {
	return errors.New("internal file-service identity evidence cannot be deserialized")
}

func (StorageSnapshot) MarshalJSON() ([]byte, error) {
	return nil, errors.New("internal file-service storage evidence is not serializable")
}

func (*StorageSnapshot) UnmarshalJSON([]byte) error {
	return errors.New("internal file-service storage evidence cannot be deserialized")
}

func referencedVolumes(config fileservice.Config) (map[shareconfig.VolumeID]bool, map[shareconfig.VolumeID]bool) {
	used := make(map[shareconfig.VolumeID]bool)
	writes := make(map[shareconfig.VolumeID]bool)
	for _, share := range config.Shares.Shares {
		used[share.VolumeID] = true
		for _, grant := range share.Grants {
			if grant.Access == "rw" {
				writes[share.VolumeID] = true
			}
		}
	}
	for _, export := range config.NFS.Exports {
		used[export.VolumeID] = true
		for _, client := range export.Clients {
			if client.Access == "rw" {
				writes[export.VolumeID] = true
			}
		}
	}
	return used, writes
}

func desiredVolume(config shareconfig.Config, id shareconfig.VolumeID) (shareconfig.Volume, bool) {
	for _, volume := range config.Volumes {
		if volume.ID == id {
			return volume, true
		}
	}
	return shareconfig.Volume{}, false
}

func validateIdentitySnapshot(snapshot IdentitySnapshot) error {
	if !snapshot.Complete || snapshot.Generation == 0 || snapshot.Registry.Validate() != nil ||
		snapshot.Fingerprint == [32]byte{} ||
		snapshot.UnixUIDs == nil || snapshot.UnixGIDs == nil || snapshot.Samba == nil ||
		len(snapshot.UnixUIDs) > MaxUnixIdentities || len(snapshot.UnixGIDs) > MaxUnixIdentities ||
		len(snapshot.Samba) > serviceaccounts.MaxRecords {
		return ErrNotReady
	}
	seenUIDs := make(map[uint32]bool, len(snapshot.UnixUIDs))
	for _, uid := range snapshot.UnixUIDs {
		if seenUIDs[uid] {
			return ErrInvalidEvidence
		}
		seenUIDs[uid] = true
	}
	seenGIDs := make(map[uint32]bool, len(snapshot.UnixGIDs))
	for _, gid := range snapshot.UnixGIDs {
		if seenGIDs[gid] {
			return ErrInvalidEvidence
		}
		seenGIDs[gid] = true
	}
	accounts := make(map[string]serviceaccounts.Account, len(snapshot.Registry.Accounts))
	for _, account := range snapshot.Registry.Accounts {
		accounts[account.ID] = account
	}
	seenSMB := make(map[string]bool, len(snapshot.Samba))
	for _, identity := range snapshot.Samba {
		journal := identity.Journal
		account, exists := accounts[journal.Account.ID]
		if journal.Validate() != nil || !exists || !sameAccountIdentity(journal.Account, account) || seenSMB[journal.Account.ID] {
			return ErrInvalidEvidence
		}
		seenSMB[journal.Account.ID] = true
	}
	return nil
}

func validateSMBAccounts(policy shareconfig.Config, snapshot IdentitySnapshot) error {
	bound, err := snapshot.Registry.BindShares(policy)
	if err != nil {
		return ErrNotReady
	}
	byID := make(map[string]SambaIdentity, len(snapshot.Samba))
	for _, identity := range snapshot.Samba {
		byID[identity.Journal.Account.ID] = identity
	}
	for _, account := range bound.Accounts {
		identity, ok := byID[account.ID]
		if !slices.Contains(snapshot.UnixUIDs, account.UID) || !slices.Contains(snapshot.UnixGIDs, account.GID) ||
			!ok || identity.Journal.Phase != smbprovision.Enabled ||
			!sameAccountIdentity(identity.Journal.Account, account) || identity.Observation.Present == false ||
			identity.Observation.Disabled || identity.Observation.Name != account.Name ||
			identity.Observation.UID != account.UID || identity.Observation.GID != account.GID ||
			identity.Observation.SID == "" || identity.Observation.SID != identity.Journal.SID {
			return ErrNotReady
		}
	}
	return nil
}

func sameAccountIdentity(first, second serviceaccounts.Account) bool {
	return first.ID == second.ID && first.Name == second.Name && first.UID == second.UID && first.GID == second.GID
}

func validateNFSIdentities(policy nfsconfig.Policy, snapshot IdentitySnapshot) error {
	uids := make(map[uint32]bool, len(snapshot.UnixUIDs))
	for _, uid := range snapshot.UnixUIDs {
		uids[uid] = true
	}
	gids := make(map[uint32]bool, len(snapshot.UnixGIDs))
	for _, gid := range snapshot.UnixGIDs {
		gids[gid] = true
	}
	for _, export := range policy.Exports {
		for _, client := range export.Clients {
			if !uids[client.AnonymousUID] || !gids[client.AnonymousGID] {
				return ErrNotReady
			}
		}
	}
	return nil
}

func validateStorageSnapshot(snapshot StorageSnapshot, policy shareconfig.Config) error {
	if !snapshot.Complete || snapshot.Generation == 0 || snapshot.Volumes == nil || len(snapshot.Volumes) > MaxObservedVolumes {
		return ErrNotReady
	}
	known := make(map[shareconfig.VolumeID]bool, len(policy.Volumes))
	for _, volume := range policy.Volumes {
		known[volume.ID] = true
	}
	seenIDs := make(map[shareconfig.VolumeID]bool, len(snapshot.Volumes))
	seenUUIDs := make(map[shareconfig.FilesystemUUID]bool, len(snapshot.Volumes))
	seenMounts := make(map[uint64]bool, len(snapshot.Volumes))
	seenDevices := make(map[[2]uint32]bool, len(snapshot.Volumes))
	for _, volume := range snapshot.Volumes {
		if !known[volume.VolumeID] || seenIDs[volume.VolumeID] || seenUUIDs[volume.FilesystemUUID] ||
			seenMounts[volume.MountID] || seenDevices[[2]uint32{volume.DeviceMajor, volume.DeviceMinor}] ||
			volume.MountID == 0 || volume.DeviceMajor == 0 ||
			volume.MountPath != path.Join(shareconfig.VolumeMountRoot, string(volume.VolumeID)) ||
			(volume.Compatibility != CompatibilityQualified && volume.Compatibility != CompatibilityUnqualified) {
			return ErrInvalidEvidence
		}
		if validateLogicalVolume(volume.VolumeID, volume.FilesystemUUID) != nil {
			return ErrInvalidEvidence
		}
		seenIDs[volume.VolumeID] = true
		seenUUIDs[volume.FilesystemUUID] = true
		seenMounts[volume.MountID] = true
		seenDevices[[2]uint32{volume.DeviceMajor, volume.DeviceMinor}] = true
	}
	return nil
}

func validateLogicalVolume(id shareconfig.VolumeID, uuid shareconfig.FilesystemUUID) error {
	config := shareconfig.Config{
		Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 1,
		Volumes: []shareconfig.Volume{{ID: id, FilesystemUUID: uuid}},
		Users:   []shareconfig.User{}, Shares: []shareconfig.Share{},
	}
	if config.Validate() != nil || path.Clean(string(id)) != string(id) || strings.Contains(string(id), "/") {
		return ErrInvalidEvidence
	}
	return nil
}

var _ json.Marshaler = Plan{}
