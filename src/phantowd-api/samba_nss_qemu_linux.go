//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

// Derive candidate NSS using the actual disposable Owner/passdb and mounted
// roster. Desired state alone round-trips; credentials, journals, live daemon
// NSS and exports are untouched. No candidate is installed or used to launch.
func exerciseQEMUOwnerSambaNSSPlan(ctx context.Context, owner *identityowner.Owner, mounted *mountowner.MountedVolumeSet, account serviceaccounts.Account) error {
	if ctx == nil || owner == nil || mounted == nil || !qemuSMBEnrollmentAccount(account) {
		return errors.New("Owner NSS fixture requires its fixed disposable authorities")
	}
	before, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		return errors.New("Owner NSS initial evidence unavailable")
	}
	if err := owner.SetDesiredState(ctx, before.Registry.Revision, account.ID, serviceaccounts.Enabled); err != nil {
		return errors.New("Owner NSS desired enable refused")
	}
	config := emptyQEMUFileServiceConfig()
	config.Shares.Volumes = []shareconfig.Volume{{ID: qemuPlannerVolumeID, FilesystemUUID: qemuNFSVolumeUUID}}
	config.Shares.Users = []shareconfig.User{{ID: account.ID, Name: account.Name}}
	config.Shares.Shares = []shareconfig.Share{{ID: "books", Name: "Books", VolumeID: qemuPlannerVolumeID,
		RelativePath: "books", Grants: []shareconfig.Grant{{UserID: account.ID, Access: "ro"}}}}
	current, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		return errors.New("Owner NSS enabled evidence unavailable")
	}
	plan, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, mounted)
	if err != nil {
		return errors.New("Owner NSS locked candidate refused")
	}
	passwd, group, nss, err := plan.SambaNSSCandidates()
	if err != nil || len(passwd)+len(group)+len(nss) > fileserviceplan.MaxSambaNSSBytes ||
		!unixidentity.FilesOnlyNSS([]byte(nss)) ||
		!strings.Contains(passwd, fmt.Sprintf("%s:!:%d:%d::/:/sbin/nologin\n", account.Name, account.UID, account.GID)) ||
		!strings.Contains(group, fmt.Sprintf("%s:!:%d:\n", account.Name, account.GID)) {
		return errors.New("Owner NSS candidate lost exact locked private identity")
	}
	observed, err := unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
	if err != nil {
		return errors.New("Owner NSS independent parser refused candidate")
	}
	enabled := account
	enabled.State = serviceaccounts.Enabled
	if status, err := observed.Assess(enabled); err != nil || status != unixidentity.Observed {
		return errors.New("Owner NSS independent assessment did not resolve native account")
	}
	reserved, err := observed.Reservations()
	if err != nil || len(reserved.UIDs) != 3 || len(reserved.GIDs) != 3 || len(reserved.Names) != 3 {
		return errors.New("Owner NSS exposed unrelated local identities")
	}
	freshness := plan.Freshness()
	if freshness.IdentityFingerprint != current.Fingerprint || freshness.IdentityGeneration != current.Registry.Revision {
		return errors.New("Owner NSS lost locked evidence binding")
	}
	identity, err := fileserviceplan.IdentityFromOwner(ctx, owner)
	if err != nil {
		return errors.New("Owner NSS census control unavailable")
	}
	var storage fileserviceplan.StorageSnapshot
	if err := mounted.WithEvidence(func(evidence mountowner.MountedVolumeSetEvidence) error {
		var err error
		storage, err = fileserviceplan.StorageFromMountedOwnerSet(evidence)
		return err
	}); err != nil {
		return errors.New("Owner NSS mounted census control unavailable")
	}
	for _, omitUID := range []bool{true, false} {
		missing := identity
		if omitUID {
			missing.UnixUIDs = []uint32{}
		} else {
			missing.UnixGIDs = []uint32{}
		}
		refused, err := fileserviceplan.Build(config, 0, missing, storage)
		if !errors.Is(err, fileserviceplan.ErrNotReady) {
			return errors.New("Owner NSS accepted missing granted Unix number")
		}
		p, g, n, err := refused.SambaNSSCandidates()
		if !errors.Is(err, fileserviceplan.ErrNotReady) || p != "" || g != "" || n != "" {
			return errors.New("Owner NSS refusal leaked a partial candidate")
		}
	}
	if err := owner.SetDesiredState(ctx, current.Registry.Revision, account.ID, serviceaccounts.Disabled); err != nil {
		return errors.New("Owner NSS desired-state restoration refused")
	}
	after, err := owner.FileServiceSnapshot(ctx)
	if err != nil || after.Registry.Revision != before.Registry.Revision+2 ||
		!slices.Equal(before.Registry.Accounts, after.Registry.Accounts) ||
		!slices.Equal(before.Native, after.Native) || !slices.Equal(before.Samba, after.Samba) ||
		!slices.Equal(before.Passdb, after.Passdb) {
		return errors.New("Owner NSS desired round-trip changed native/Samba identity evidence")
	}
	stale := freshness
	stale.IdentityGeneration, stale.IdentityFingerprint = after.Registry.Revision, after.Fingerprint
	if plan.FreshAgainst(stale) {
		return errors.New("Owner NSS old candidate survived desired-state drift")
	}
	refused, err := fileserviceplan.BuildFromOwners(ctx, config, 0, owner, mounted)
	if !errors.Is(err, fileserviceplan.ErrNotReady) {
		return errors.New("Owner NSS granted disabled desired account")
	}
	if _, _, _, err := refused.SambaNSSCandidates(); !errors.Is(err, fileserviceplan.ErrNotReady) {
		return errors.New("Owner NSS disabled refusal produced a candidate")
	}
	fmt.Println("PHANTOWD_M41_OWNER_SAMBA_NSS_READY identity=owner_passdb storage=mounted_roster locks=ordered native_private_groups=true files_only=true census_refusals=2 desired_roundtrip=true journals_unchanged=true stale_refused=true installed=false activation=false scope=disposable-qemu-only")
	return nil
}
