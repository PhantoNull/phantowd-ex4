//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const ownerNFSRoot = "/srv/phantowd/volumes/qemu-plan/nfs-owner"
const ownerNFSClient = "/run/phantowd-nfs-owner-client"
const ownerNFSPolicy = "/run/phantowd-nfs-owner-policy"

// Fixed disposable-guest composition only, with original retained inputs.
type ownerNFSQEMU struct {
	identity      *identityowner.Owner
	identityLease *identityowner.FileServiceLease
	storage       *mountowner.MountedVolumeSet
	storageLease  *mountowner.MountedVolumeSetLease
	roots         *nfsowner.ExportRootsQEMU
	policySeed    *naspolicystore.Store
	policyOwner   *naspolicystore.Owner
	policyLease   *naspolicystore.Lease
	management    *qemuNASPolicyHTTP
	kernel        *nfskernel.ControllerQEMU
	helpers       [2]*ownerNFSChild
	options       string
	access        string
	phase         string
	uid, gid      uint32
	exported      bool
}

type ownerNFSChild struct {
	command *exec.Cmd
	done    chan error
}
type ownerNFSReview struct {
	constructionreview.Marker
	backend *ownerNFSQEMU
	owner   *nfsowner.Owner
	cause   error
}

func (r *ownerNFSReview) Error() string {
	return "NFS activation retains original sources for review: phase=" + r.backend.phase
}
func (r *ownerNFSReview) Unwrap() error { return r.cause }

func runQEMUNFSOwnerActivation() error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := mountowner.WithQEMUMountedSet(smbFixtureAnchor, func(set *mountowner.MountedVolumeSet) (result error) {
		b := &ownerNFSQEMU{storage: set, phase: "prepare", access: "ro"}
		var owner *nfsowner.Owner
		defer func() {
			// No release or retry after uncertainty. The returned review object
			// keeps the original authority alive through fixture teardown.
			if result != nil {
				result = &ownerNFSReview{backend: b, owner: owner, cause: result}
			}
		}()
		var err error
		b.uid, b.gid, err = qemuIdentityOwnerAPIIdentity()
		if err != nil {
			return err
		}
		const authority = "/run/phantowd-nfs-owner-identity"
		for _, p := range []string{authority, authority + "/registry", authority + "/operations"} {
			if err := os.Mkdir(p, 0700); err != nil {
				return err
			}
		}
		seed, err := serviceaccountstore.Open(authority + "/registry")
		if err != nil {
			return err
		}
		if err := errors.Join(seed.Initialize(23000, 23010), seed.Close()); err != nil {
			return err
		}
		// No imported identities exist in this guarded synthetic guest. The
		// Owner independently reads the actual /etc Unix census on each check.
		b.identity, err = identityowner.Open(authority, func(context.Context) (serviceaccounts.Reservations, error) {
			return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
		})
		if err != nil {
			return err
		}
		config := emptyQEMUFileServiceConfig()
		config.Shares.Volumes = []shareconfig.Volume{{ID: qemuPlannerVolumeID, FilesystemUUID: qemuNFSVolumeUUID}}
		config.NFS.Exports = []nfsconfig.Export{{ID: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", VolumeID: qemuPlannerVolumeID, RelativePath: "nfs-owner",
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "ro", Squash: "all", AnonymousUID: b.uid, AnonymousGID: b.gid, Security: "sys"}}}}
		document := naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: 1, FileServices: config,
			ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
				Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
		if err := b.retainPolicy(ctx, document); err != nil {
			return err
		}
		b.management, err = newQEMUNASPolicyHTTP(b.policyOwner)
		if err != nil {
			return err
		}
		before, err := os.ReadFile(ownerNFSPolicy + "/nas-services.json")
		if err != nil {
			return err
		}
		identity, err := b.identity.FileServiceSnapshot(ctx)
		if err != nil {
			return err
		}
		b.identityLease, err = b.identity.RetainFileServiceSnapshot(ctx, identity.Fingerprint)
		if err != nil {
			return err
		}
		plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, b.policyLease, 0, b.identityLease, set)
		if err != nil {
			return err
		}
		candidate, err := plan.NFSv3TCPCandidate()
		if err != nil {
			return err
		}
		b.storageLease, _, err = set.Acquire(ctx)
		if err != nil {
			return err
		}
		if err := os.Mkdir(ownerNFSRoot, 0700); err != nil {
			return err
		}
		if err := os.Chown(ownerNFSRoot, int(b.uid), int(b.gid)); err != nil {
			return err
		}
		if err := os.WriteFile(ownerNFSRoot+"/marker", []byte("owner-derived-nfs\n"), 0644); err != nil {
			return err
		}
		b.roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, b.storageLease)
		if err != nil {
			return err
		}
		enabled, table, roots, err := candidate.Documents()
		lines := strings.Split(strings.TrimSpace(table), "\n")
		if err != nil || !enabled || len(roots) != 1 || len(lines) != 2 || !matchesQEMUOwnerMountedExport(lines[1], ownerNFSRoot, b.uid, b.gid) {
			return errors.New("NFS generated policy differs from the fixed owner fixture")
		}
		peer := strings.Fields(lines[1])[1]
		b.options = strings.TrimSuffix(strings.TrimPrefix(peer, "127.0.0.1/32("), ")")
		owner, err = nfsowner.NewQEMU(candidate, b)
		if err != nil {
			return err
		}
		b.phase = "start"
		if err := owner.Start(ctx); err != nil {
			return fmt.Errorf("owner-start: %w", err)
		}
		b.phase = "client"
		if err := os.Mkdir(ownerNFSClient, 0700); err != nil {
			return err
		}
		if err := b.command(ctx, "/bin/mount", "-t", "nfs", "-o", "rw,vers=3,proto=tcp,nolock,soft,timeo=5,retrans=1", "127.0.0.1:"+ownerNFSRoot, ownerNFSClient); err != nil {
			return err
		}
		mounts, err := os.ReadFile("/proc/mounts")
		_, tail, found := strings.Cut(string(mounts), "127.0.0.1:"+ownerNFSRoot+" "+ownerNFSClient+" nfs ")
		opts := "," + strings.SplitN(tail, " ", 2)[0] + ","
		if err != nil || !found || !strings.HasPrefix(opts, ",rw,") || !strings.Contains(opts, ",vers=3,") || !strings.Contains(opts, ",proto=tcp,") {
			return errors.New("NFS client is not the exact read-write NFSv3/TCP mount")
		}
		data, err := os.ReadFile(ownerNFSClient + "/marker")
		if err != nil || string(data) != "owner-derived-nfs\n" {
			return errors.New("NFS owner client read differs")
		}
		f, err := os.OpenFile(ownerNFSClient+"/denied", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if f != nil {
			_ = f.Close()
		}
		if !errors.Is(err, syscall.EROFS) {
			return errors.New("read-only export did not refuse write with EROFS")
		}
		if _, err := os.Lstat(ownerNFSRoot + "/denied"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("denied NFS write changed storage")
		}
		b.phase = "policy-update-held"
		next, err := b.policyLease.Snapshot(ctx)
		if err != nil || len(next.FileServices.NFS.Exports) != 1 || len(next.FileServices.NFS.Exports[0].Clients) != 1 {
			return errors.New("NFS desired-policy claim lost its original export")
		}
		next.Revision++
		next.FileServices.Revision++
		next.FileServices.Shares.Revision++
		next.FileServices.NFS.Revision++
		next.FileServices.NFS.VolumeRevision++
		next.ISCSI.Revision++
		next.ISCSI.VolumeRevision++
		next.FileServices.NFS.Exports[0].Clients[0].Access = "rw"
		if next.Validate() != nil || b.management.exchange(ctx, &next, 503) != nil {
			return errors.New("running NFS did not exclude a valid desired-policy update")
		}
		if err := owner.Check(ctx); err != nil {
			return fmt.Errorf("owner-check: %w", err)
		}
		b.phase = "stop"
		if err := b.command(ctx, "/bin/umount", ownerNFSClient); err != nil {
			return err
		}
		if err := owner.Stop(ctx); err != nil {
			return fmt.Errorf("owner-stop: %w", err)
		}
		if b.policyLease.Verify(ctx) != nil || b.management.exchange(ctx, &next, 503) != nil {
			return errors.New("NFS stop released desired-policy authority before close")
		}
		b.phase = "close"
		if err := owner.Close(ctx); err != nil {
			return err
		}
		if !errors.Is(b.policyLease.Verify(ctx), naspolicystore.ErrClosed) {
			return errors.New("closed NFS retained a live desired-policy claim")
		}
		after, err := os.ReadFile(ownerNFSPolicy + "/nas-services.json")
		if err != nil || !bytes.Equal(before, after) {
			return errors.New("NFS activation or refused updates changed desired policy")
		}
		b.phase = "policy-update-after-close"
		if err := b.management.exchange(ctx, &next, 200); err != nil {
			return fmt.Errorf("closed NFS did not release desired-policy mutation: %w", err)
		}
		updated, err := b.policyOwner.Snapshot(ctx)
		if err != nil || updated.Revision != next.Revision || len(updated.FileServices.NFS.Exports) != 1 ||
			len(updated.FileServices.NFS.Exports[0].Clients) != 1 || updated.FileServices.NFS.Exports[0].Clients[0].Access != "rw" {
			return errors.New("desired-policy update after NFS close was not observed")
		}
		if err := b.reapplySavedPolicy(ctx, owner); err != nil {
			return err
		}
		if err := b.management.exchange(ctx, nil, 200); err != nil {
			return err
		}
		b.management.server.Close()
		for _, p := range []string{ownerNFSRoot + "/updated", ownerNFSRoot + "/marker", ownerNFSRoot} {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
		if err := b.identity.Close(); err != nil {
			return err
		}
		return b.policyOwner.Close()
	})
	if err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_OWNER_ACTIVATION_READY original_identity=true original_storage=true generated_policy=true owner_running=true kernel_backend=true activation=true read=true write=EROFS stopped=true sources_released=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_POLICY_ACTIVATION_READY original_policy=true revision=1 update_while_running=busy active_bytes_unchanged=true update_after_close=committed released_after_stop=true kernel_backend=true activation=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_POLICY_REAPPLY_READY revision=2 lifetimes=2 original_policy=true fresh_claims=true read=true write=sync-verified uid_gid=verified old_owner=inert teardown=clean kernel_backend=true activation=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NAS_POLICY_HTTP_READY original_owner=true protocols=smb,nfs,iscsi busy_while_running=true commit_after_close=true revision=2 nfs_reapplied=true scope=qemu-loopback-only")
	return nil
}

// Bootstrap only this synthetic guest document through the existing store.
// Uncertain setup retains the original writer. Consumer operations receive
// neither this document nor a replacement configuration/backend per call.
func (b *ownerNFSQEMU) retainPolicy(ctx context.Context, document naspolicy.Config) error {
	if err := document.Validate(); err != nil {
		return err
	}
	if err := os.Mkdir(ownerNFSPolicy, 0700); err != nil {
		return err
	}
	var err error
	b.policySeed, err = naspolicystore.Open(ownerNFSPolicy)
	if err != nil {
		return err
	}
	if err := b.policySeed.Commit(0, document); err != nil {
		return err
	}
	if err := b.policySeed.Close(); err != nil {
		return err
	}
	b.policySeed = nil
	b.policyOwner, err = naspolicystore.OpenOwner(ownerNFSPolicy)
	if err != nil {
		return err
	}
	b.policyLease, err = b.policyOwner.Acquire(ctx, document.Revision)
	return err
}

func (b *ownerNFSQEMU) CheckInputs(ctx context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, b.policyLease, 0, b.identityLease, b.storage)
	if err != nil {
		return err
	}
	if !candidate.FreshAgainst(plan.Freshness()) {
		return errors.New("NFS retained sources changed")
	}
	return b.roots.Check(ctx)
}

func (b *ownerNFSQEMU) VerifyStopped(ctx context.Context) error {
	if b.exported || b.helpers[0] != nil || b.helpers[1] != nil {
		return errors.New("NFS consumers remain")
	}
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil || strings.Contains(string(mounts), " "+ownerNFSClient+" ") {
		return errors.New("NFS client absence uncertain")
	}
	if b.kernel != nil {
		return b.kernel.CheckStopped(ctx)
	}
	threads, e1 := os.ReadFile("/proc/fs/nfsd/threads")
	versions, e2 := os.ReadFile("/proc/fs/nfsd/versions")
	ports, e3 := os.ReadFile("/proc/fs/nfsd/portlist")
	return errors.Join(e1, e2, e3, nfskernel.ValidateProfileQEMU(threads, versions, ports, false))
}

func (b *ownerNFSQEMU) Start(ctx context.Context) error {
	before, err := runQEMUExportfsContext(ctx, "-s")
	if err != nil || len(normalizedQEMUExportLines(before)) != 0 {
		return errors.New("NFS fixture requires empty export table")
	}
	b.kernel, err = nfskernel.OpenSmokeQEMU(ctx)
	if err != nil {
		return err
	}
	b.helpers[0], err = startOwnerNFSChild("/usr/sbin/rpcbind", "-f", "-h", "127.0.0.1")
	if err != nil {
		return err
	}
	if err := b.waitRPC(ctx, "100000", "4"); err != nil {
		return err
	}
	if err := b.kernel.Start(ctx); err != nil {
		return err
	}
	b.helpers[1], err = startOwnerNFSChild("/usr/sbin/rpc.mountd", "-F", "-N", "2", "-N", "4", "-V", "3", "-p", "20048")
	if err != nil {
		return err
	}
	if err := b.waitRPC(ctx, "100005", "3"); err != nil {
		return err
	}
	b.exported = true // Retain ownership even if exportfs completion is uncertain.
	_, err = runQEMUExportfsContext(ctx, "-i", "-o", b.options, "127.0.0.1/32:"+ownerNFSRoot)
	return err
}

func (b *ownerNFSQEMU) VerifyReady(ctx context.Context) error {
	if err := b.kernel.CheckRunning(ctx); err != nil {
		return err
	}
	for _, child := range b.helpers {
		if child == nil {
			return errors.New("NFS helper absent")
		}
		select {
		case err := <-child.done:
			return errors.Join(errors.New("NFS helper exited"), err)
		default:
		}
	}
	current, err := runQEMUExportfsContext(ctx, "-s")
	lines := normalizedQEMUExportLines(current)
	if err != nil || len(lines) != 1 || !matchesQEMUOwnerMountedExportAccess(lines[0], ownerNFSRoot, b.uid, b.gid, b.access) {
		return errors.New("NFS live export differs from generated policy")
	}
	return nil
}

func (b *ownerNFSQEMU) Stop(ctx context.Context) error {
	if b.kernel != nil {
		if err := b.kernel.Stop(ctx); err != nil {
			return err
		}
	}
	if b.exported {
		if _, err := runQEMUExportfsContext(ctx, "-u", "127.0.0.1/32:"+ownerNFSRoot); err != nil {
			return err
		}
		out, err := runQEMUExportfsContext(ctx, "-s")
		if err != nil || len(normalizedQEMUExportLines(out)) != 0 {
			return errors.New("NFS export removal uncertain")
		}
		b.exported = false
	}
	for i := len(b.helpers) - 1; i >= 0; i-- {
		if b.helpers[i] == nil {
			continue
		}
		if err := b.helpers[i].stop(ctx); err != nil {
			return err
		}
		b.helpers[i] = nil
	}
	return nil
}

func (b *ownerNFSQEMU) Release(ctx context.Context) error {
	if b.kernel != nil {
		if err := b.kernel.Close(ctx); err != nil {
			return err
		}
	}
	if err := b.roots.Close(); err != nil {
		return err
	}
	// Dataset and shared identity/policy Owners belong to the parent fixture.
	if err := os.Remove(ownerNFSClient); err != nil {
		return err
	}
	for _, close := range []func() error{b.storageLease.Close, b.identityLease.Release, b.policyLease.Release} {
		if err := close(); err != nil {
			return err
		}
	}
	return nil
}

func (b *ownerNFSQEMU) command(ctx context.Context, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("NFS command %s: %w", path, err)
	}
	return nil
}

func (b *ownerNFSQEMU) waitRPC(ctx context.Context, program, version string) error {
	for {
		if b.command(ctx, "/usr/bin/rpcinfo", "-T", "tcp", "127.0.0.1", program, version) == nil {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

func startOwnerNFSChild(path string, args ...string) (*ownerNFSChild, error) {
	// Owner.Start's short context ends on return; it must not kill healthy children.
	cmd := exec.Command(path, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	child := &ownerNFSChild{command: cmd, done: make(chan error, 1)}
	go func() { child.done <- cmd.Wait() }()
	return child, nil
}

func (child *ownerNFSChild) stop(ctx context.Context) error {
	if err := child.command.Process.Signal(syscall.SIGTERM); err != nil {
		return err
	}
	select {
	case err := <-child.done:
		var exit *exec.ExitError
		if err == nil || errors.As(err, &exit) && exit.ProcessState.Sys().(syscall.WaitStatus).Signal() == syscall.SIGTERM {
			return nil
		}
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}
