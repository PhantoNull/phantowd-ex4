//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

// Keep ORIGINAL parents, handles and errors after any uncertain/intentional
// fault. No fixture disposal is represented as product recovery or settlement.
var sourceRuntimeRetained any
var sourceRuntimeCause error

type sourceOwnerFault uint8

const (
	ownerNoFault sourceOwnerFault = iota
	ownerPolicyLoss
	ownerScheduledDaemonLoss
	ownerStopDaemonLoss
	ownerRPCStartFailure
	ownerKernelConstructRefusal
	ownerKernelBindRefusal
)

func probeSourceRuntime(ctx context.Context, expected []byte) (result error) {
	return probeSourceRuntimeMode(ctx, expected, false, false, ownerNoFault)
}

func probeSourceLossRuntime(ctx context.Context, expected []byte) error {
	return probeSourceRuntimeMode(ctx, expected, true, false, ownerNoFault)
}

func probeSourceDaemonLossRuntime(ctx context.Context, expected []byte) error {
	return probeSourceRuntimeMode(ctx, expected, true, true, ownerNoFault)
}

func probeSourceRuntimeMode(ctx context.Context, expected []byte, sourceLoss, daemonLoss bool, ownerFault sourceOwnerFault) (result error) {
	if ownerFault > ownerKernelBindRefusal || daemonLoss && !sourceLoss || ownerFault != ownerNoFault && (sourceLoss || daemonLoss) {
		return errors.New("mixed source fault modes")
	}
	phase := "mount-roster"
	defer func() {
		sourceRuntimeCause = result // ORIGINAL retaining error, never only its text.
		if result != nil {
			fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_SOURCE_FAILURE phase=%s\n", phase)
		}
	}()
	return mountowner.WithQEMUNFSSourceMountedSet(ctx, func(set *mountowner.MountedVolumeSet) error {
		lease, evidence, err := set.Acquire(ctx)
		if err != nil {
			return err
		}
		storage, err := fileserviceplan.StorageFromMountedOwnerSet(evidence)
		if err != nil || len(storage.Volumes) != 1 {
			return errors.New("source fixture lacks complete actual mounted roster")
		}
		volume := storage.Volumes[0]
		for _, name := range []string{"books", "archive", "denied"} {
			if err := os.Mkdir(filepath.Join(volume.MountPath, name), 0700); err != nil {
				return err // Exclusive fixture preparation, never in a constructor.
			}
			if err := os.Chown(filepath.Join(volume.MountPath, name), 1000, 1000); err != nil {
				return err
			}
		}
		marker := filepath.Join(volume.MountPath, "archive/marker")
		if err := os.WriteFile(marker, []byte("phantowd-source-private-ro\n"), 0400); err != nil {
			return err
		}
		if err := os.Chown(marker, 1000, 1000); err != nil {
			return err
		}
		config := fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: 1,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: 1,
				Volumes: []shareconfig.Volume{{ID: volume.VolumeID, FilesystemUUID: volume.FilesystemUUID}}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
				Exports: []nfsconfig.Export{
					{ID: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", VolumeID: volume.VolumeID, RelativePath: "books",
						Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}},
					{ID: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", VolumeID: volume.VolumeID, RelativePath: "archive",
						Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "ro", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}},
					{ID: "cccccccc-dddd-eeee-ffff-aaaaaaaaaaaa", VolumeID: volume.VolumeID, RelativePath: "denied",
						Clients: []nfsconfig.Client{{Network: "192.0.2.0/24", Access: "ro", Squash: "all", AnonymousUID: 1000, AnonymousGID: 1000, Security: "sys"}}}}}}
		phase = "policy-identity-owners"
		authority, err := prepareSourcePolicy(ctx, config, set)
		if err != nil {
			return err
		}
		build := func(generation uint64) (fileserviceplan.NFSv3Candidate, error) {
			return authority.candidate(ctx, generation-1)
		}
		candidate, err := build(1)
		if err != nil {
			return err
		}
		phase = "original-input-pair"
		inputs, err := runtimebundle.PrepareNFSSourceInputPairQEMU(ctx, expected, candidate)
		if err != nil {
			return err
		}
		var roots *nfsowner.ExportRootsQEMU
		var joined *nfsowner.SourceRuntimeQEMU
		defer func() {
			sourceRuntimeRetained = struct {
				roster *mountowner.MountedVolumeSet
				lease  *mountowner.MountedVolumeSetLease
				roots  *nfsowner.ExportRootsQEMU
				joined *nfsowner.SourceRuntimeQEMU
				inputs [2]*runtimebundle.NFSInputsQEMU
			}{set, lease, roots, joined, inputs}
		}()
		before, err := sourceFDCount()
		if err != nil {
			return err
		}
		roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, lease)
		if err != nil {
			return err
		}
		phase = "policy-admission"
		if err := authority.verifyAdmission(ctx, roots, inputs[0]); err != nil {
			return err
		}
		phase = "normal-binding"
		joined, err = nfsowner.NewLeasedSourceRuntimeQEMU(ctx, roots, inputs[0], authority.policy, authority.identityRef, set, 0)
		if err != nil {
			return err
		}
		copyJoin := *joined
		if copyJoin.Check(ctx) == nil || copyJoin.Close() == nil {
			return errors.New("copied source/runtime join accepted")
		}
		if value, err := nfsowner.NewSourceRuntimeQEMU(ctx, roots, inputs[1]); value != nil || !errors.Is(err, nfsowner.ErrBusy) {
			return errors.New("duplicate source join admitted")
		}
		canceled, cancel := context.WithCancel(ctx)
		cancel()
		if !errors.Is(joined.Check(canceled), context.Canceled) || joined.Check(ctx) != nil ||
			!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs[0].Close(), processowner.ErrBusy) ||
			!errors.Is(lease.Close(), mountowner.ErrBusy) {
			return errors.New("live join failed cancellation or parent closure exclusion")
		}
		if authority.policy.Verify(ctx) != nil || authority.identityRef.Verify(ctx) != nil {
			return errors.New("source runtime consumed original policy or identity claim")
		}
		fmt.Println("PHANTOWD_NFS_SOURCE_POLICY_READY original_policy_lease=true original_identity_lease=true unix_census=true registry=empty_fixture complete_candidate=true parent_close_excluded=true released_claims_refused=true mismatch_refused=true canceled_unchanged=true no_claim_release=true product=false scope=qemu-only")
		phase = "original-source-nfs-access"
		if ownerFault == ownerRPCStartFailure || ownerFault == ownerKernelConstructRefusal || ownerFault == ownerKernelBindRefusal {
			phase = "partial-rpc-start"
			return runSourceOwnerPartialStart(ctx, joined, authority, roots, inputs[0], lease, ownerFault)
		}
		if ownerFault == ownerScheduledDaemonLoss || ownerFault == ownerStopDaemonLoss {
			phase = "periodic-owner-daemon-loss"
			if ownerFault == ownerStopDaemonLoss {
				phase = "explicit-owner-stop-loss"
			}
			return runSourceOwnerDaemonLoss(ctx, joined, authority, roots, inputs[0], lease, ownerFault == ownerStopDaemonLoss)
		}
		if ownerFault == ownerPolicyLoss {
			phase = "periodic-owner-policy-loss"
			return runSourceOwnerPolicyLoss(ctx, joined, authority, roots, inputs[0], lease)
		}
		if sourceLoss {
			phase = "live-source-replacement"
			probe := joined.ProbeSourceLossFixtureQEMU
			if daemonLoss {
				probe = joined.ProbeSourceDaemonLossFixtureQEMU
			}
			if err := probe(ctx); err != nil {
				return err
			}
			retained, err := sourceFDCount()
			if err != nil || !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.Close(), nfsowner.ErrReviewRequired) ||
				!errors.Is(joined.RunAccessFixtureQEMU(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.ProbeSourceLossFixtureQEMU(ctx), nfsowner.ErrReviewRequired) ||
				!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs[0].Close(), processowner.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) ||
				!errors.Is(inputs[0].Check(ctx), runtimebundle.ErrReviewRequired) {
				return errors.New("live source loss released original authorities")
			}
			if after, err := sourceFDCount(); err != nil || after != retained {
				return errors.New("review released live-consumer references")
			}
			fmt.Println("PHANTOWD_NFS_SOURCE_LOSS_READY original_sources=true same_payload_replacement=true live_client=true held_file=true binding_mismatch=true restored_refused=true unmount_ebusy=true kernel_and_daemons_live=true original_refs_retained=true forced_unmount=false restart=false settlement=false product=false scope=qemu-only")
			if daemonLoss {
				phase = "source-mountd-exit"
				canceled, cancel := context.WithCancel(ctx)
				cancel()
				if !errors.Is(joined.InjectSourceMountdExitFixtureQEMU(canceled), context.Canceled) || copyJoin.InjectSourceMountdExitFixtureQEMU(ctx) == nil {
					return errors.New("invalid fault admission accepted")
				}
				if err := joined.InjectSourceMountdExitFixtureQEMU(ctx); err != nil {
					return err
				}
				if !errors.Is(joined.InjectSourceMountdExitFixtureQEMU(ctx), runtimebundle.ErrReviewRequired) {
					return errors.New("mountd fault repeated")
				}
				fmt.Println("PHANTOWD_NFS_SOURCE_DAEMON_LOSS_READY source_review=true original_mountd_exit=true mountd_review=true kernel_and_rpcbind_live=true original_refs_retained=true client_file_cached=true stop_attempted=false restart=false product=false scope=qemu-only")
			}
			phase = "source-loss-withdrawal"
			canceled, cancel := context.WithCancel(ctx)
			cancel()
			if !errors.Is(joined.WithdrawSourceLossFixtureQEMU(canceled), context.Canceled) {
				return errors.New("pre-admission cancellation not preserved")
			}
			if err := joined.WithdrawSourceLossFixtureQEMU(ctx); err != nil {
				return err
			}
			retained, err = sourceFDCount()
			if err != nil || !errors.Is(joined.WithdrawSourceLossFixtureQEMU(ctx), runtimebundle.ErrReviewRequired) ||
				!errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.Close(), nfsowner.ErrReviewRequired) ||
				!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs[0].Close(), processowner.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
				return errors.New("withdrawal revived or released reviewed authority")
			}
			if after, err := sourceFDCount(); err != nil || after != retained {
				return errors.New("withdrawal review released references")
			}
			fmt.Println("PHANTOWD_NFS_SOURCE_WITHDRAW_READY admitted_cancel=true independent_cleanup=true exports_withdrawn=true kernel_stopped=true daemons_stopped=true listeners_absent=true client_mounts_retained=true cached_file_identity=true review_retained=true stop_once=true forced_unmount=false restart=false quiescence=false product=false scope=qemu-only")
			return nil
		}
		if err := joined.RunAccessFixtureQEMU(ctx); err != nil {
			return err
		}
		if joined.Close() != nil || joined.Close() != nil || joined.Check(ctx) == nil || roots.Check(ctx) != nil || inputs[0].Check(ctx) != nil {
			return errors.New("clean unstarted join release failed")
		}
		if roots.Close() != nil {
			return errors.New("normal source closure failed")
		}
		if after, err := sourceFDCount(); err != nil || after != before {
			return errors.New("normal source/join leaked descriptors")
		}
		phase = "same-text-different-evidence"
		changed, err := build(2)
		if err != nil {
			return err
		}
		_, a, _, _ := candidate.Documents()
		_, b, _, _ := changed.Documents()
		if a != b || candidate.EquivalentTo(changed) {
			return errors.New("changed-evidence source oracle invalid")
		}
		wrongRoots, err := nfsowner.NewExportRootsQEMU(ctx, changed, lease)
		if err != nil {
			return err
		}
		if value, err := nfsowner.NewSourceRuntimeQEMU(ctx, wrongRoots, inputs[0]); value != nil || !errors.Is(err, runtimebundle.ErrMismatch) ||
			wrongRoots.Check(ctx) != nil || wrongRoots.Close() != nil || inputs[0].Check(ctx) != nil {
			return errors.New("different source evidence admitted or original inputs poisoned")
		}
		if lease.Close() != nil || inputs[0].Close() != nil || inputs[0].Check(ctx) == nil {
			return errors.New("normal parents could not close after release")
		}
		phase = "source-fault-binding"
		lease, _, err = set.Acquire(ctx)
		if err != nil {
			return err
		}
		roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, lease)
		if err != nil {
			return err
		}
		joined, err = nfsowner.NewLeasedSourceRuntimeQEMU(ctx, roots, inputs[1], authority.policy, authority.identityRef, set, 0)
		if err != nil || joined.Check(ctx) != nil {
			return errors.New("fault fixture failed original join")
		}
		phase = "source-replacement"
		leaf, saved := filepath.Join(volume.MountPath, "books"), filepath.Join(volume.MountPath, "books.original")
		if err := os.Rename(leaf, saved); err != nil {
			return err
		}
		if err := os.Mkdir(leaf, 0700); err != nil || !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) {
			return errors.New("source replacement admitted")
		}
		if err := os.Remove(leaf); err != nil {
			return err
		}
		if err := os.Rename(saved, leaf); err != nil {
			return err
		}
		phase = "restored-source-retained-review"
		retained, err := sourceFDCount()
		if err != nil || !errors.Is(joined.Check(ctx), nfsowner.ErrReviewRequired) || !errors.Is(joined.Close(), nfsowner.ErrReviewRequired) ||
			!errors.Is(roots.Close(), nfsowner.ErrBusy) || !errors.Is(inputs[1].Close(), processowner.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) ||
			inputs[1].Check(ctx) != nil {
			return errors.New("restoration released original source/runtime authorities")
		}
		if after, err := sourceFDCount(); err != nil || after != retained {
			return errors.New("review released original references")
		}
		fmt.Println("PHANTOWD_NFS_SOURCE_READY original_roster=true roots=3 input_pair=true complete_candidate=true parent_closure_excluded=true copied_refused=true duplicate_refused=true canceled_unchanged=true mismatch_rollback=true normal_fd_balance=true source_replacement_review=true restored_refused=true original_refs_retained=true daemons=false kernel_backend=false product=false scope=disposable-qemu-only")
		return nil
	})
}

func sourceFDCount() (int, error) {
	entries, err := os.ReadDir("/proc/self/fd")
	return len(entries), err
}
