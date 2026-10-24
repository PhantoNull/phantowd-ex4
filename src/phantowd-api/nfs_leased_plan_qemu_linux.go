//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
)

type nfsLeasedPlanReviewQEMU struct {
	constructionreview.Marker
	owner     *naspolicystore.Owner
	policy    *naspolicystore.Lease
	identity  *identityowner.FileServiceLease
	directory string
	cause     error
}

func (*nfsLeasedPlanReviewQEMU) Error() string   { return "NAS planning fixture retains review" }
func (e *nfsLeasedPlanReviewQEMU) Unwrap() error { return e.cause }

// Called only by the fixed disposable mounted-volume/identity guest fixture.
// Only preparation writes a synthetic policy under /tmp. No export-root
// capture, service activation or credential mutation occurs in this exercise.
func exerciseQEMUNFSLeasedPlan(ctx context.Context, config fileservice.Config, identity *identityowner.Owner, storage *mountowner.MountedVolumeSet, expected fileserviceplan.Plan) (result error) {
	directory, err := os.MkdirTemp("/tmp", "phantowd-nfs-leased-plan-")
	if err != nil {
		return err
	}
	held := &nfsLeasedPlanReviewQEMU{directory: directory}
	defer func() {
		// Any unexpected failure retains original errors/references; never retry
		// cleanup or release other authority following an uncertain outcome.
		if result != nil {
			held.cause = result
			result = held
			return
		}
		if err := held.owner.Close(); err != nil {
			held.cause = err
			result = held
			return
		}
		result = os.RemoveAll(directory)
	}()
	document := naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: config.Revision, FileServices: config,
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: config.Revision, VolumeRevision: config.Shares.Revision,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
	if err := document.Validate(); err != nil {
		return err
	}
	encoded, err := json.Marshal(document)
	if err != nil {
		return err
	}
	path := filepath.Join(directory, "nas-services.json")
	if err := os.WriteFile(path, encoded, 0600); err != nil {
		return err
	}
	held.owner, err = naspolicystore.OpenOwner(directory)
	if err != nil {
		return err
	}
	held.policy, err = held.owner.Acquire(ctx, document.Revision)
	if err != nil {
		return err
	}
	held.identity, err = identity.RetainFileServiceSnapshot(ctx, expected.Freshness().IdentityFingerprint)
	if err != nil {
		return err
	}
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, held.policy, 0, held.identity, storage)
	if err != nil {
		return err
	}
	smb, nfs := plan.RenderedCandidates()
	expectedSMB, expectedNFS := expected.RenderedCandidates()
	if !plan.FreshAgainst(expected.Freshness()) || smb != expectedSMB || nfs != expectedNFS ||
		!slices.Equal(plan.RequiredVolumes(), expected.RequiredVolumes()) {
		return errors.New("retained NAS plan differs from complete expected candidate")
	}
	next := document
	next.Revision++
	next.FileServices.Revision++
	next.FileServices.Shares.Revision++
	next.FileServices.NFS.Revision++
	next.FileServices.NFS.VolumeRevision++
	next.ISCSI.Revision++
	next.ISCSI.VolumeRevision++
	if next.Validate() != nil || !errors.Is(held.owner.Commit(ctx, document.Revision, next), naspolicystore.ErrBusy) ||
		held.policy.Verify(ctx) != nil || held.identity.Verify(ctx) != nil {
		return errors.New("retained planning claims did not preserve original authority")
	}
	if err := held.identity.Release(); err != nil {
		return err
	}
	refused, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, held.policy, 0, held.identity, storage)
	if !errors.Is(err, fileserviceplan.ErrNotReady) || !errors.Is(err, identityowner.ErrUnavailable) || refused.FreshAgainst(refused.Freshness()) {
		return errors.New("released identity supplied a partial or valid plan")
	}
	if err := held.policy.Release(); err != nil {
		return err
	}
	refused, err = fileserviceplan.BuildFromLeasedNASOwners(ctx, held.policy, 0, held.identity, storage)
	if !errors.Is(err, fileserviceplan.ErrNotReady) || !errors.Is(err, naspolicystore.ErrClosed) || refused.FreshAgainst(refused.Freshness()) {
		return errors.New("released policy supplied a partial or valid plan")
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(encoded, after) {
		return errors.New("read-only planning changed synthetic policy bytes")
	}
	fmt.Println("PHANTOWD_NFS_LEASED_PLAN_READY policy=original_lease identity=original_lease storage=mounted_owner complete_candidate=true mutation_blocked=true released_refused=true planner_writes=false root_capture=false activation=false scope=disposable-qemu-only")
	return nil
}
