//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const plannedStartupMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_STARTUP_READY owner=actual_native_backend storage=mounted_roster same_authorities=true granted_only=true service_role=true original_views=true before_start_busy=true after_start_busy=true duplicate_refused=true canceled_start_refused=true fresh_observation=true runtime_close_before_release=true stopped_reaped=true no_fd_leak=true samba_data=false activation=false scope=qemu-only"

const plannedDataMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_DATA_READY same_authorities=true same_daemon=true granted_only=true ungranted_enabled_denied=true smb_read=true smb_write=true unix_owner=true readonly_EROFS=true readonly_denied=true symlink_denied=true fresh_observation=true stopped_before_release=true no_fd_leak=true activation=false scope=qemu-only"

// A NEW disposable service in a fresh, independently enrolled data guest.
// It retains the SAME identity Owner, startup-fixed backend, complete mounted
// roster and original share pins from planning through startup and full Close.
// A separate access proof exercises actual transfers through that SAME service.
// The startup marker alone claims neither transfers nor product activation.
func nativePlannedStartupFixtureQEMU(plan *runtimebundle.Plan, lookup fileserviceplan.SambaEnrollmentLookup, authority string, inventory identityowner.Inventory) (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	var callers [3]*os.File
	for index, path := range []string{"/run/phantowd-samba-code", "/run/phantowd-native-samba-root/etc", "/run/phantowd-native-samba-state"} {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return err
		}
		callers[index] = os.NewFile(uintptr(fd), "planned-startup-original-caller")
	}
	runtime, err := plan.NewNativeSambaRuntimeQEMU(ctx, callers[0], callers[1], callers[2], lookup)
	for _, caller := range callers {
		err = errors.Join(err, caller.Close())
	}
	if err != nil {
		return err
	}
	defer func() { reportNativeWorkerFailureQEMU(runtime, result) }()
	backend, err := smbexec.NewNativeBackendQEMU(ctx, runtime)
	if err != nil {
		return err
	}
	owner, err := identityowner.OpenWithSMBBackend(authority, inventory, backend)
	if err != nil {
		return err
	}
	var stage *plannedConfigurationStageQEMU
	if err := mountowner.WithQEMUNativeMountedSet(func(storage *mountowner.MountedVolumeSet) error {
		before, err := owner.FileServiceSnapshot(ctx)
		if err != nil || len(before.Registry.Accounts) != 2 || before.Registry.Accounts[1].Name != "qpsecond" {
			return errors.New("planned startup complete identity evidence")
		}
		peer := before.Registry.Accounts[1]
		if peer.State != serviceaccounts.Disabled {
			return errors.New("planned startup unexpected desired identity")
		}
		if err := owner.SetDesiredState(ctx, before.Registry.Revision, peer.ID, serviceaccounts.Enabled); err != nil {
			return err
		}
		// A genuinely enabled credential must still have no service access when
		// it has no grant. Never fabricate passdb/SID evidence or mistake an
		// already-disabled account for grant enforcement.
		ungranted := before.Registry.Accounts[0]
		if ungranted.Name != "qpmanaged" || ungranted.State != serviceaccounts.Disabled {
			return errors.New("planned data unexpected ungranted identity")
		}
		op := owner.SMB(ungranted.ID)
		journal, err := op.Load(ctx)
		if err != nil || journal.Phase != smbprovision.Enabled || journal.SID == "" {
			return errors.New("planned data missing confirmed enabled ungranted credential")
		}
		current, _, err := owner.Snapshot(ctx)
		if err != nil {
			return err
		}
		if err := owner.SetDesiredState(ctx, current.Revision, ungranted.ID, serviceaccounts.Enabled); err != nil {
			return err
		}
		const source = "/run/phantowd-samba-source"
		const root = "/run/phantowd/service-handoff/native-planned-startup"
		for _, name := range []string{"planned-readonly", "planned-writable"} {
			path := source + "/" + name
			if err := os.Mkdir(path, 0770); err != nil {
				return err
			}
			if err := errors.Join(os.Chown(path, int(peer.UID), int(peer.GID)), os.Chmod(path, 0770)); err != nil {
				return err
			}
		}
		for _, path := range []string{source + "/planned-readonly/seed", "/run/native-share-upload"} {
			file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
			if err != nil {
				return err
			}
			_, err = file.WriteString("native-share-qualified")
			if err := errors.Join(err, file.Close()); err != nil {
				return err
			}
		}
		if err := os.Chown(source+"/planned-readonly/seed", int(peer.UID), int(peer.GID)); err != nil {
			return err
		}
		if err := os.Symlink(source+"/planned-readonly/seed", source+"/planned-readonly/escape"); err != nil {
			return err
		}
		config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
				Volumes: []shareconfig.Volume{{ID: mountowner.QEMUNativeVolumeID, FilesystemUUID: mountowner.QEMUNativeFilesystemUUID}},
				Users:   []shareconfig.User{{ID: peer.ID, Name: peer.Name}}, Shares: []shareconfig.Share{
					{ID: "readonly", Name: "ReadOnly", VolumeID: mountowner.QEMUNativeVolumeID, RelativePath: "planned-readonly", Grants: []shareconfig.Grant{{UserID: peer.ID, Access: "ro"}}},
					{ID: "writable", Name: "Writable", VolumeID: mountowner.QEMUNativeVolumeID, RelativePath: "planned-writable", Grants: []shareconfig.Grant{{UserID: peer.ID, Access: "rw"}}},
				}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1, Exports: []nfsconfig.Export{}},
		}
		compiled, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, storage)
		if err != nil {
			return err
		}
		roles, err := compiled.SambaRoleCandidate()
		if err != nil {
			return err
		}
		candidate, err := roles.ServiceCandidate()
		if err != nil {
			return err
		}
		_, _, _, _, requests, err := candidate.Documents()
		if err != nil || len(requests) != 2 {
			return errors.New("planned startup exact share declarations")
		}
		if err := os.MkdirAll("/run/phantowd/service-handoff", 0755); err != nil {
			return err
		}
		if err := os.Mkdir(root, 0710); err != nil {
			return err
		}
		if err := errors.Join(os.Chown(root, 0, 1000), os.Chmod(root, 0710)); err != nil {
			return err
		}
		shares := make([]mountowner.ServiceShare, len(requests))
		for index, request := range requests {
			shares[index] = mountowner.ServiceShare{ID: request.ID, VolumeID: string(request.VolumeID),
				RelativePath: request.RelativePath, ReadOnly: request.ReadOnly}
		}
		handoff, err := mountowner.NewServiceHandoff(root, storage, shares, 1000)
		if err != nil {
			return err
		}
		if _, err := handoff.Mount(ctx); err != nil {
			return err
		}
		pins, err := handoff.RetainShareRootsQEMU()
		if err != nil {
			return err
		}
		stage, err = stagePlannedConfigurationQEMU(ctx, runtime, roles)
		if err != nil {
			return err
		}
		service, err := smbexec.NewNativePlannedServiceQEMU(ctx, smbexec.NativePlannedInputsQEMU{
			Policy: config, Identity: owner, Storage: storage, Shares: pins, Backend: backend,
		})
		if err != nil {
			return fmt.Errorf("planned startup authority construction: %w", err)
		}
		// No defer releases authority after an uncertain operation. Only explicit
		// successful full closure admits caller release; failure disposes the guest.
		if !errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
			return errors.New("planned startup released authority before start")
		}
		canceled, cancelStart := context.WithCancel(ctx)
		cancelStart()
		if err := service.Start(canceled); !errors.Is(err, context.Canceled) {
			return errors.New("planned startup admitted canceled start")
		}
		if err := service.Start(ctx); err != nil {
			return fmt.Errorf("planned same-authority daemon start: %w", err)
		}
		if !errors.Is(service.Start(ctx), runtimebundle.ErrReviewRequired) ||
			!errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
			return errors.New("planned live service retried or released authority")
		}
		if err := service.Observe(ctx); err != nil {
			return err
		}
		status, err := service.Status()
		if err != nil || status.State != "ready" || status.Checks != 1 || !status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed {
			return errors.New("planned startup incomplete live observation")
		}
		// The original startup/preparation remains bounded40. Data access is a
		// NEW action with its OWN20-second budget, not leftovers from startup.
		// Guest180/readiness12/worker4/stop bounds remain unchanged.
		cancel()
		dataCtx, cancelData := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancelData()
		ctx = dataCtx
		canceledData, cancelProbe := context.WithCancel(ctx)
		cancelProbe()
		if err := service.VerifyDataAccess(canceledData); !errors.Is(err, context.Canceled) {
			return errors.New("planned data accepted canceled probe")
		}
		if err := service.VerifyDataAccess(ctx); err != nil {
			return fmt.Errorf("planned same-authority data access: %w", err)
		}
		if !errors.Is(service.VerifyDataAccess(ctx), runtimebundle.ErrReviewRequired) {
			return errors.New("planned data repeated a single-use probe")
		}
		status, err = service.Status()
		if err != nil || !status.DataVerified || status.State != "ready" || !status.IdentityRetained || !status.SharesRetained ||
			!errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
			return errors.New("planned data lost continuous service authority")
		}
		if err := service.Close(context.Background()); err != nil {
			return err
		}
		status, err = service.Status()
		if err != nil || status.State != "stopped" || status.IdentityRetained || status.SharesRetained || !status.RuntimeClosed {
			return errors.New("planned startup released authorities before full runtime close")
		}
		if err := handoff.Close(); err != nil {
			return err
		}
		current, _, err = owner.Snapshot(ctx)
		if err != nil {
			return err
		}
		if err := owner.SetDesiredState(ctx, current.Revision, peer.ID, serviceaccounts.Disabled); err != nil {
			return err
		}
		for _, path := range []string{root, source + "/planned-readonly/escape", source + "/planned-readonly/seed",
			source + "/planned-writable/created", source + "/planned-readonly", source + "/planned-writable",
			"/run/native-share-upload", "/run/native-share-download-rw", "/run/native-share-download-ro"} {
			if err := os.Remove(path); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	if err := owner.Close(); err != nil {
		return err
	}
	return stage.removeAfterRuntimeClose()
}
