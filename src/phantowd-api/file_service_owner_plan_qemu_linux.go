//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

func exerciseQEMUOwnerFileServicePlan(ctx context.Context, owner *identityowner.Owner) (fileserviceplan.Plan, fileserviceplan.IdentitySnapshot, error) {
	identity, err := fileserviceplan.IdentityFromOwner(ctx, owner)
	if err != nil {
		return fileserviceplan.Plan{}, fileserviceplan.IdentitySnapshot{}, errors.New("QEMU Owner identity evidence could not be adapted")
	}
	config := emptyQEMUFileServiceConfig()
	storage := fileserviceplan.StorageSnapshot{Complete: true, Generation: 1, Volumes: []fileserviceplan.ObservedVolume{}}
	plan, err := fileserviceplan.Build(config, 0, identity, storage)
	if err != nil {
		return fileserviceplan.Plan{}, fileserviceplan.IdentitySnapshot{}, errors.New("QEMU Owner evidence did not produce a candidate plan")
	}
	freshness := plan.Freshness()
	if !plan.FreshAgainst(freshness) {
		return fileserviceplan.Plan{}, fileserviceplan.IdentitySnapshot{}, errors.New("QEMU Owner candidate lost evidence freshness")
	}
	fmt.Println("PHANTOWD_FILE_SERVICE_OWNER_PLAN_READY identity=owner_observed fingerprint_bound=true policy=empty storage=synthetic_empty activation=false http=false scope=qemu-only")
	return plan, identity, nil
}

// exerciseQEMUOwnerMountedNFSPlan composes the actual Owner identity snapshot
// with a generation-bound mount tuple observed from the separate disposable
// ext2 fixture. It is deliberately NFS-only: this proves local UID/GID and
// volume evidence can meet in one candidate without creating a Samba account,
// changing authentication, or activating a service.
func exerciseQEMUOwnerMountedNFSPlan(ctx context.Context, owner *identityowner.Owner) error {
	if ctx == nil || owner == nil {
		return errors.New("QEMU Owner/mount planner requires its fixed fixture owners")
	}
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	return mountowner.WithQEMUMountedSetEvidence(smbFixtureAnchor, func(mountedSet mountowner.MountedVolumeSetEvidence) error {
		mountedVolumes := mountedSet.Volumes()
		if !mountedSet.Complete() || mountedSet.Generation() == 0 || len(mountedVolumes) != 1 {
			return errors.New("QEMU Owner/mount planner did not receive its complete fixed volume roster")
		}
		mounted := mountedVolumes[0]
		if mounted.VolumeID() != string(qemuPlannerVolumeID) || mounted.FilesystemUUID() != qemuNFSVolumeUUID ||
			mounted.MountPath() != shareconfig.VolumeMountRoot+"/"+string(qemuPlannerVolumeID) ||
			mounted.Compatibility() != fileserviceplan.CompatibilityQualified || mounted.Generation() == 0 ||
			mounted.MountID() == 0 || mounted.DeviceMajor() == 0 || mounted.ReadOnly() {
			return errors.New("QEMU Owner/mount planner received unexpected mounted-volume evidence")
		}
		identity, err := fileserviceplan.IdentityFromOwner(ctx, owner)
		if err != nil || !identity.Complete || len(identity.Registry.Accounts) != 1 || len(identity.Samba) != 0 {
			return errors.New("QEMU Owner/mount planner could not obtain complete identity-only evidence")
		}
		account := identity.Registry.Accounts[0]
		if account.ID != qemuOwnerAccountID || account.Name != qemuOwnerAccount || account.State != serviceaccounts.Enabled ||
			account.UID < qemuOwnerFirstUID || account.UID > qemuOwnerLastUID ||
			!slices.Contains(identity.UnixUIDs, account.UID) || !slices.Contains(identity.UnixGIDs, account.GID) {
			return errors.New("QEMU Owner/mount planner identity is missing from the local Unix census")
		}

		storage, err := fileserviceplan.StorageFromMountedOwnerSet(mountedSet)
		if err != nil || !storage.Complete || storage.Generation != mountedSet.Generation() ||
			storage.OwnerFingerprint != mountedSet.Fingerprint() || len(storage.Volumes) != 1 {
			return errors.New("QEMU Owner/mount evidence was not adapted as a complete storage snapshot")
		}
		config := fileservice.Config{
			Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
			Shares: shareconfig.Config{
				Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 1,
				Volumes: []shareconfig.Volume{{ID: qemuPlannerVolumeID, FilesystemUUID: qemuNFSVolumeUUID}},
				Users:   []shareconfig.User{}, Shares: []shareconfig.Share{},
			},
			NFS: nfsconfig.Policy{
				Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
				Exports: []nfsconfig.Export{{
					ID: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", VolumeID: qemuPlannerVolumeID, RelativePath: "books",
					Clients: []nfsconfig.Client{{
						Network: "127.0.0.1/32", Access: "ro", Squash: "all",
						AnonymousUID: account.UID, AnonymousGID: account.GID, Security: "sys",
					}},
				}},
			},
		}
		plan, err := fileserviceplan.Build(config, 0, identity, storage)
		if err != nil {
			return errors.New("QEMU Owner/mount evidence did not produce a non-empty NFS candidate")
		}
		bindings := plan.RequiredVolumes()
		_, exports := plan.RenderedCandidates()
		freshness := plan.Freshness()
		staleIdentity := freshness
		staleIdentity.IdentityFingerprint[0] ^= 1
		staleMount := freshness
		staleMount.StorageFingerprint[0] ^= 1
		if len(bindings) != 1 || bindings[0].VolumeID != qemuPlannerVolumeID ||
			bindings[0].FilesystemUUID != qemuNFSVolumeUUID || bindings[0].MountPath != mounted.MountPath() ||
			bindings[0].MountID != mounted.MountID() || bindings[0].DeviceMajor != mounted.DeviceMajor() ||
			bindings[0].DeviceMinor != mounted.DeviceMinor() || bindings[0].ReadOnly != mounted.ReadOnly() ||
			!strings.Contains(exports, mounted.MountPath()+"/books") ||
			!strings.Contains(exports, fmt.Sprintf("anonuid=%d,anongid=%d", account.UID, account.GID)) ||
			!strings.Contains(exports, "127.0.0.1/32(ro,") ||
			!plan.FreshAgainst(freshness) || plan.FreshAgainst(staleIdentity) || plan.FreshAgainst(staleMount) {
			return errors.New("QEMU Owner/mount candidate did not preserve identity, storage, or read-only policy binding")
		}
		if _, err := json.Marshal(plan); err == nil {
			return errors.New("QEMU Owner/mount plan became serializable")
		}
		if err := validateQEMUOwnerMountedExportfs(ctx, exports, mounted.MountPath(), account.UID, account.GID); err != nil {
			return err
		}
		fmt.Println("PHANTOWD_FILE_SERVICE_OWNER_MOUNTED_PLAN_READY identity=owner_observed storage=complete_mounted_owner_set owner_scope=fixture_complete volume_count=1 uid_gid=local_census nfs=read_only identity_stale=true mount_stale=true candidate_only=true auth_mutation=false activation=false http=false scope=disposable-qemu-only")
		fmt.Println("PHANTOWD_FILE_SERVICE_OWNER_MOUNTED_EXPORTFS_READY target_parser=accepted_and_withdrawn owner_tuple=true read_only=true identity_mapping=true persistent_export=false scope=disposable-qemu-only")
		return nil
	})
}

// exerciseQEMUOwnerLockCoherentNFSPlan compiles a non-empty NFS candidate from
// one live identity Owner and the disposable mounted-volume roster. The SMB
// policy remains empty so this fixture does not create a Samba section or
// change credentials; the NFS text is inspected without loading exports or
// activating a service.
func exerciseQEMUOwnerLockCoherentNFSPlan(ctx context.Context, owner *identityowner.Owner, account serviceaccounts.Account) error {
	if ctx == nil || owner == nil || !qemuSMBEnrollmentAccount(account) {
		return errors.New("QEMU coherent Owner/storage plan requires the fixed SMB identity fixture")
	}
	config := fileservice.Config{
		Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 2,
		Shares: shareconfig.Config{
			Format: shareconfig.Format, SchemaVersion: shareconfig.SchemaVersion, Revision: 2,
			Volumes: []shareconfig.Volume{{ID: qemuPlannerVolumeID, FilesystemUUID: qemuNFSVolumeUUID}},
			Users:   []shareconfig.User{}, Shares: []shareconfig.Share{},
		},
		NFS: nfsconfig.Policy{
			Format: nfsconfig.Format, SchemaVersion: 1, Revision: 2, VolumeRevision: 2,
			Exports: []nfsconfig.Export{{
				ID: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", VolumeID: qemuPlannerVolumeID,
				RelativePath: "books", Clients: []nfsconfig.Client{{
					Network: "127.0.0.1/32", Access: "ro", Squash: "all",
					AnonymousUID: account.UID, AnonymousGID: account.GID, Security: "sys",
				}},
			}},
		},
	}
	before, err := owner.FileServiceSnapshot(ctx)
	if err != nil || before.Fingerprint == ([32]byte{}) || len(before.Samba) != 1 || len(before.Passdb) != 2 {
		return errors.New("QEMU coherent plan fixture could not obtain complete passdb-backed identity evidence")
	}
	return mountowner.WithQEMUMountedSet(smbFixtureAnchor, func(mountedSet *mountowner.MountedVolumeSet) error {
		plan, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, mountedSet)
		if err != nil {
			return errors.New("QEMU planner could not compile under identity and storage Owner locks")
		}
		bindings := plan.RequiredVolumes()
		samba, exports := plan.RenderedCandidates()
		freshness := plan.Freshness()
		if len(bindings) != 1 || bindings[0].VolumeID != qemuPlannerVolumeID ||
			bindings[0].FilesystemUUID != qemuNFSVolumeUUID ||
			bindings[0].MountPath != shareconfig.VolumeMountRoot+"/"+string(qemuPlannerVolumeID) ||
			bindings[0].MountID == 0 || bindings[0].DeviceMajor == 0 || bindings[0].ReadOnly ||
			freshness.PolicyRevision != config.Revision || freshness.ActiveRevision != 0 ||
			freshness.IdentityFingerprint != before.Fingerprint || freshness.StorageGeneration == 0 ||
			freshness.StorageFingerprint == ([32]byte{}) || !plan.FreshAgainst(freshness) ||
			!strings.Contains(exports, bindings[0].MountPath+"/books ") ||
			!strings.Contains(exports, "127.0.0.1/32(ro,") ||
			!strings.Contains(exports, fmt.Sprintf("anonuid=%d,anongid=%d", account.UID, account.GID)) ||
			!strings.Contains(exports, "all_squash") {
			return errors.New("QEMU lock-coherent plan lost its Owner, mount, NFS or readonly identity binding")
		}
		for _, line := range strings.Split(strings.TrimSpace(samba), "\n") {
			if line != "" && !strings.HasPrefix(line, "#") {
				return errors.New("QEMU NFS-only candidate unexpectedly contains a Samba section")
			}
		}
		if _, err := json.Marshal(plan); err == nil {
			return errors.New("QEMU lock-coherent plan became serializable")
		}
		after, err := owner.FileServiceSnapshot(ctx)
		if err != nil || after.Fingerprint != before.Fingerprint {
			return errors.New("QEMU candidate construction changed or invalidated identity/passdb evidence")
		}
		fmt.Println("PHANTOWD_M41_OWNER_STORAGE_COHERENT_READY identity=owner_passdb_fingerprint storage=mounted_roster locks=ordered nfs=readonly samba=empty_policy candidate=true activation=false endpoint=false auth_mutation=false scope=disposable-qemu-only")
		return nil
	})
}

// validateQEMUOwnerMountedExportfs applies the candidate only to the fixed,
// disposable guest export table while the synthetic mount-owner fixture is
// live. This is parser integration evidence, not part of plan construction or
// product activation. The exact export file and child directory are always
// removed and the prior export table must be restored before returning.
func validateQEMUOwnerMountedExportfs(ctx context.Context, rendered, mountPath string, uid, gid uint32) (result error) {
	const (
		fixtureMount = "/srv/phantowd/volumes/qemu-plan"
		exportsDir   = "/etc/exports.d"
		fixturePath  = "/etc/exports.d/phantowd-owner-mounted-plan.exports"
		fixtureFSID  = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
	)
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || runtime.GOOS != "linux" || runtime.GOARCH != "arm" || mountPath != fixtureMount {
		return errors.New("Owner-mounted exportfs fixture requires its fixed root-only ARM QEMU mount")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("Owner-mounted exportfs fixture requires the disposable Versatile PB guest")
	}
	const candidateHeader = "# PhantoWD candidate exports; verify identities, containment and credentials before activation."
	if len(rendered) == 0 || len(rendered) > 8192 {
		return errors.New("Owner-mounted exportfs candidate exceeds its bound")
	}
	candidateLines := strings.Split(strings.TrimSpace(rendered), "\n")
	if len(candidateLines) != 2 || strings.TrimSpace(candidateLines[0]) != candidateHeader || strings.TrimSpace(candidateLines[1]) == "" {
		return errors.New("Owner-mounted exportfs candidate is not one bounded entry")
	}
	line := strings.TrimSpace(candidateLines[1])
	booksPath := filepath.Join(fixtureMount, "books")
	if !strings.Contains(line, booksPath+" ") || !strings.Contains(line, "127.0.0.1/32(") ||
		!strings.Contains(line, "all_squash") || !strings.Contains(line, fmt.Sprintf("anonuid=%d,anongid=%d", uid, gid)) ||
		!strings.Contains(line, "fsid="+fixtureFSID) || !strings.Contains(line, "mountpoint="+fixtureMount) ||
		strings.Contains(line, "127.0.0.1/32(rw,") {
		return errors.New("Owner-mounted exportfs candidate lost its fixed path, read-only policy, identity or filesystem ID")
	}
	if _, err := os.Lstat(fixtureMount); err != nil {
		return errors.New("Owner-mounted exportfs fixture mount is unavailable")
	}
	exportsDirCreated := false
	if info, err := os.Lstat(exportsDir); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(exportsDir, 0755); err != nil {
			return errors.New("Owner-mounted exportfs fixture configuration directory could not be created")
		}
		exportsDirCreated = true
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0022 != 0 {
		return errors.New("Owner-mounted exportfs fixture configuration directory is unsafe")
	}
	defer func() {
		if exportsDirCreated {
			if err := os.Remove(exportsDir); err != nil {
				result = errors.Join(result, errors.New("Owner-mounted exportfs fixture configuration directory could not be removed"))
			} else {
				exportsDirCreated = false
			}
		}
	}()
	if _, err := os.Lstat(fixturePath); !errors.Is(err, os.ErrNotExist) {
		return errors.New("Owner-mounted exportfs fixture configuration already exists")
	}
	baseline, err := runQEMUExportfsContext(ctx, "-s")
	if err != nil {
		return errors.New("Owner-mounted exportfs baseline could not be read")
	}
	baselineLines := normalizedQEMUExportLines(baseline)
	if strings.Contains(string(baseline), booksPath) || strings.Contains(string(baseline), "fsid="+fixtureFSID) {
		return errors.New("Owner-mounted exportfs fixture conflicts with an existing export")
	}
	booksCreated := false
	if info, err := os.Lstat(booksPath); errors.Is(err, os.ErrNotExist) {
		if err := os.Mkdir(booksPath, 0700); err != nil {
			return errors.New("Owner-mounted exportfs fixture directory could not be created")
		}
		booksCreated = true
	} else if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("Owner-mounted exportfs fixture path is not a directory")
	}
	exportFileCreated := false
	cleanup := func() error {
		var cleanupErr error
		if exportFileCreated {
			cleanupContext := context.WithoutCancel(ctx)
			if err := os.Remove(fixturePath); err != nil {
				cleanupErr = errors.Join(cleanupErr, errors.New("Owner-mounted exportfs fixture file could not be removed"))
			}
			if _, err := runQEMUExportfsContext(cleanupContext, "-r"); err != nil {
				cleanupErr = errors.Join(cleanupErr, errors.New("Owner-mounted exportfs entry could not be withdrawn"))
			} else if current, err := runQEMUExportfsContext(cleanupContext, "-s"); err != nil || !slices.Equal(normalizedQEMUExportLines(current), baselineLines) {
				cleanupErr = errors.Join(cleanupErr, errors.New("Owner-mounted exportfs table was not restored to its baseline"))
			}
		}
		if booksCreated {
			if err := os.Remove(booksPath); err != nil {
				cleanupErr = errors.Join(cleanupErr, errors.New("Owner-mounted exportfs fixture directory could not be removed"))
			} else {
				booksCreated = false
			}
		}
		return cleanupErr
	}
	defer func() { result = errors.Join(result, cleanup()) }()

	file, err := os.OpenFile(fixturePath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return errors.New("Owner-mounted exportfs fixture configuration could not be created")
	}
	exportFileCreated = true
	_, writeErr := file.WriteString(line + "\n")
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || syncErr != nil || closeErr != nil {
		return errors.New("Owner-mounted exportfs fixture configuration could not be written")
	}
	if _, err := runQEMUExportfsContext(ctx, "-r"); err != nil {
		return errors.New("target exportfs rejected the Owner-mounted candidate")
	}
	accepted, err := runQEMUExportfsContext(ctx, "-s")
	if err != nil {
		return errors.New("target exportfs result could not be observed")
	}
	additional := subtractQEMUExportLines(normalizedQEMUExportLines(accepted), baselineLines)
	if len(additional) != 1 || !matchesQEMUOwnerMountedExport(additional[0], booksPath, uid, gid) {
		return errors.New("target exportfs did not preserve Owner-mounted path, read-only access and numeric identity")
	}
	return nil
}

func matchesQEMUOwnerMountedExport(line, expectedPath string, uid, gid uint32) bool {
	fields := strings.Fields(line)
	if len(fields) != 2 || fields[0] != expectedPath {
		return false
	}
	open := strings.IndexByte(fields[1], '(')
	if open <= 0 || !strings.HasSuffix(fields[1], ")") || fields[1][:open] != "127.0.0.1/32" {
		return false
	}
	options := strings.Split(fields[1][open+1:len(fields[1])-1], ",")
	seen := make(map[string]bool, len(options))
	for _, option := range options {
		if option == "" || seen[option] {
			return false
		}
		seen[option] = true
	}
	return seen["ro"] && !seen["rw"] && seen["all_squash"] &&
		seen[fmt.Sprintf("anonuid=%d", uid)] && seen[fmt.Sprintf("anongid=%d", gid)] &&
		seen["fsid=bbbbbbbb-cccc-dddd-eeee-ffffffffffff"]
}

func runQEMUExportfsContext(parent context.Context, args ...string) ([]byte, error) {
	if parent == nil {
		return nil, errors.New("fixed QEMU exportfs command requires a context")
	}
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/sbin/exportfs", args...)
	output := &qemuExportfsOutput{}
	command.Stdout = output
	command.Stderr = output
	err := command.Run()
	if err != nil || output.overflow {
		clear(output.data)
		return nil, errors.New("fixed QEMU exportfs command failed or exceeded its output bound")
	}
	return append([]byte(nil), output.data...), nil
}

type qemuExportfsOutput struct {
	data     []byte
	overflow bool
}

func (output *qemuExportfsOutput) Write(value []byte) (int, error) {
	const outputLimit = 64 * 1024
	remaining := outputLimit - len(output.data)
	if remaining <= 0 || len(value) > remaining {
		if remaining > 0 {
			output.data = append(output.data, value[:remaining]...)
		}
		output.overflow = true
		return 0, errors.New("fixed QEMU exportfs output exceeded its bound")
	}
	output.data = append(output.data, value...)
	return len(value), nil
}

func normalizedQEMUExportLines(output []byte) []string {
	var lines []string
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) > 0 {
			lines = append(lines, strings.Join(fields, " "))
		}
	}
	slices.Sort(lines)
	return lines
}

func subtractQEMUExportLines(current, baseline []string) []string {
	remaining := append([]string(nil), baseline...)
	var additional []string
	for _, line := range current {
		index := slices.Index(remaining, line)
		if index < 0 {
			additional = append(additional, line)
			continue
		}
		remaining = slices.Delete(remaining, index, index+1)
	}
	if len(remaining) > 0 {
		return append([]string{"baseline-entry-missing"}, additional...)
	}
	return additional
}
