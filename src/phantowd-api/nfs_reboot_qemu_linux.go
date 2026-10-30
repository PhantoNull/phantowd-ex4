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
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/mountguard"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const qemuNFSRebootInstallation = "60606060606060606060606060606060"

var errQEMURebootNFS = errors.New("fixed NFS reboot fixture requires review")

// Single dedicated PID1 invocation. On any uncertainty these original references
// remain reachable until the disposable guest exits; no cleanup/retry/adoption.
var qemuNFSRebootRetained []*qemuNFSReboot

type qemuNFSReboot struct {
	source *os.File
	mount  *mountguard.Root
	seed   *naspolicystore.Store
	owner  *naspolicystore.Owner
	lease  *naspolicystore.Lease
	reader *revisionstore.NASEvidenceAuthority
	rev    uint64
}

func qemuNFSRebootPolicy(rev uint64) naspolicy.Config {
	f := emptyQEMUFileServiceConfig()
	f.Revision, f.Shares.Revision, f.NFS.Revision, f.NFS.VolumeRevision = rev, rev, rev, rev
	f.Shares.Volumes = []shareconfig.Volume{{ID: qemuPlannerVolumeID, FilesystemUUID: qemuNFSVolumeUUID}}
	f.NFS.Exports = []nfsconfig.Export{{ID: "cccccccc-dddd-eeee-ffff-111111111111", VolumeID: qemuPlannerVolumeID, RelativePath: "nfs-reboot",
		Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "rw", Squash: "all", AnonymousUID: 65534, AnonymousGID: 65534, Security: "sys"}}}}
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: rev, FileServices: f,
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: rev, VolumeRevision: rev,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
}

// Both bases are independently known program data, not adopted from observed
// JSON/receipts. Only seed creates state; verify cannot initialize or repair it.
func (b *qemuNFSReboot) policy(ctx context.Context, root, phase string) error {
	if phase != "seed" && phase != "verify" {
		return errQEMURebootNFS
	}
	b.rev = 1
	if phase == "verify" {
		b.rev = 2
	}
	dir := root + "/nfs-policy"
	if phase == "seed" {
		if err := os.Mkdir(dir, 0700); err != nil {
			return err
		}
		var err error
		b.seed, err = naspolicystore.Open(dir)
		if err != nil {
			return err
		}
		if err := b.seed.Commit(0, qemuNFSRebootPolicy(1)); err != nil {
			return err
		}
		if err := b.seed.Close(); err != nil {
			return err
		}
		b.seed = nil
		if err := writeQEMUStateFixture(dir+"/nas-evidence.json", []byte(`{"format":"phantowd-nas-evidence-container","schema_version":1,"installation_id":"`+qemuNFSRebootInstallation+`"}`)); err != nil {
			return err
		}
		if err := errors.Join(syncQEMUStateDirectory(dir), syncQEMUStateDirectory(root)); err != nil {
			return err
		}
	}
	expected, err := json.Marshal(qemuNFSRebootPolicy(b.rev))
	if err != nil {
		return err
	}
	b.owner, err = naspolicystore.OpenConfirmedOwner(ctx, dir, qemuNFSRebootInstallation, expected)
	if err != nil {
		return err
	}
	b.lease, err = b.owner.Acquire(ctx, b.rev)
	return err
}

func (b *qemuNFSReboot) check(ctx context.Context) error {
	if b.mount == nil || b.source == nil || b.lease == nil || b.mount.Verify() != nil {
		return errQEMURebootNFS
	}
	return b.lease.Verify(ctx)
}

func (b *qemuNFSReboot) busy(ctx context.Context) error {
	if err := b.check(ctx); err != nil {
		return err
	}
	if !errors.Is(b.owner.Commit(ctx, b.rev, qemuNFSRebootPolicy(b.rev+1)), naspolicystore.ErrBusy) {
		return errQEMURebootNFS
	}
	return b.check(ctx)
}

func (b *qemuNFSReboot) run(phase string) error {
	if !nfskernel.RebootFixtureQEMU() || (phase != "seed" && phase != "verify") || b.mount == nil || b.source == nil || b.mount.Verify() != nil {
		return errQEMURebootNFS
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := b.policy(ctx, qemuStateAnchor, phase); err != nil {
		return err
	}
	server := qemuStateAnchor + "/nfs-reboot"
	if phase == "seed" {
		if err := os.Mkdir(server, 0755); err != nil {
			return err
		}
		f, err := os.OpenFile(server+"/marker", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		const marker = "phantowd-qemu-nfs-smoke-v1\n"
		n, writeErr := f.WriteString(marker)
		if syncErr, closeErr := f.Sync(), f.Close(); n != len(marker) || errors.Join(writeErr, syncErr, closeErr) != nil {
			return errQEMURebootNFS
		}
		if err := errors.Join(syncQEMUStateDirectory(server), syncQEMUStateDirectory(qemuStateAnchor)); err != nil {
			return err
		}
	}
	var previous *nfskernel.ControllerQEMU
	if err := runQEMUNFSKernelCycleWithReboot(ctx, int(b.rev), &previous, false, b); err != nil {
		return err
	}
	if err := b.check(ctx); err != nil {
		return err
	}
	if err := b.lease.Release(); err != nil {
		return err
	}
	if err := b.owner.Commit(ctx, b.rev, qemuNFSRebootPolicy(b.rev+1)); err != nil {
		return err
	}
	if err := b.owner.Close(); err != nil {
		return err
	}
	// Diagnostic only, after known complete fixture publication and teardown.
	var err error
	b.reader, err = revisionstore.OpenNASEvidenceAuthority(ctx, qemuStateAnchor+"/nfs-policy", qemuNFSRebootInstallation)
	if err != nil {
		return err
	}
	observed, observeErr := b.reader.Observe(ctx)
	if errors.Join(observeErr, b.reader.Close()) != nil || observed.Kind != naspolicyevidence.MatchingLocalRecords || observed.Pending || observed.Roles != 5 {
		return errQEMURebootNFS
	}
	if phase == "verify" {
		fmt.Println("PHANTOWD_NFS_REBOOT_READY boots=2 protocol=nfs3 transport=tcp kernel_backend=true activation=true read=true write=sync-verified previous_bytes=true original_policy=true ordered_writer=true receipt=verified teardown=clean scope=clean-qemu-reboot-only")
	}
	return nil
}
