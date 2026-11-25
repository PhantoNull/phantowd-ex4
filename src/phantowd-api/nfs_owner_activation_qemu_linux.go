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
	"net/netip"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

const ownerNFSRoot = "/srv/phantowd/volumes/qemu-plan/nfs-owner"
const ownerNFSClient = "/run/phantowd-nfs-owner-client"
const ownerNFSPolicy = "/run/phantowd-nfs-owner-policy"
const ownerNFSInstallation = "66666666666666666666666666666666"

// Fixed disposable-guest composition only, with original retained inputs.
type ownerNFSQEMU struct {
	identity       *identityowner.Owner
	identityLease  *identityowner.FileServiceLease
	storage        *mountowner.MountedVolumeSet
	inputs         *nfsowner.RetainedInputs
	policySeed     *naspolicystore.Store
	policyOwner    *naspolicystore.Owner
	policyLease    *naspolicystore.Lease
	policyEvidence *revisionstore.NASEvidenceAuthority
	management     *qemuNASPolicyHTTP
	phase          string
	uid, gid       uint32
}

type ownerNFSReview struct {
	constructionreview.Marker
	backend     *ownerNFSQEMU
	owner       *nfsowner.Owner
	cause       error
	contextDone bool
}

func (r *ownerNFSReview) Error() string {
	// The second lifetime retains its own backend. Preserve its failure phase
	// instead of reporting the parent's preceding policy-update phase.
	source, contextDone := r, r.contextDone
	for {
		var nested *ownerNFSReview
		if !errors.As(source.cause, &nested) {
			break
		}
		source = nested
		contextDone = contextDone || source.contextDone
	}
	return fmt.Sprintf("NFS activation retains original sources for review: phase=%s deadline=%t canceled=%t context_done=%t",
		source.backend.phase, errors.Is(r.cause, context.DeadlineExceeded), errors.Is(r.cause, context.Canceled), contextDone)
}
func (r *ownerNFSReview) Unwrap() error { return r.cause }

func runQEMUNFSOwnerActivation() error {
	if !nfskernel.SmokeFixtureQEMU() {
		return nfskernel.ErrRefused
	}
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	defaultTables, err := qemuNFSDefaultTables()
	if err != nil {
		return err
	}
	removeStateConfig, err := nfsowner.InstallManagedStateConfigQEMU(ctx)
	if err != nil {
		return err
	}
	err = mountowner.WithQEMUMountedSet(smbFixtureAnchor, func(set *mountowner.MountedVolumeSet) (result error) {
		b := &ownerNFSQEMU{storage: set, phase: "prepare"}
		var owner *nfsowner.Owner
		defer func() {
			// No release or retry after uncertainty. The returned review object
			// keeps the original authority alive through fixture teardown.
			if result != nil {
				result = &ownerNFSReview{backend: b, owner: owner, cause: result, contextDone: ctx.Err() != nil}
			}
		}()
		var err error
		if err := b.prepareFixtureSources(ctx, "127.0.0.1/32", "ro"); err != nil {
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
		var candidate fileserviceplan.NFSv3Candidate
		b.inputs, candidate, err = nfsowner.PrepareInputs(ctx, b.policyLease, b.identityLease, set, 0)
		if err != nil {
			return err
		}
		if !errors.Is(b.inputs.Check(ctx, fileserviceplan.NFSv3Candidate{}), nfsowner.ErrInvalid) {
			return errors.New("NFS input preparation accepted an unrelated candidate")
		}
		enabled, table, roots, err := candidate.Documents()
		lines := strings.Split(strings.TrimSpace(table), "\n")
		if err != nil || !enabled || len(roots) != 1 || len(lines) != 2 || !matchesQEMUOwnerMountedExport(lines[1], ownerNFSRoot, b.uid, b.gid) {
			return errors.New("NFS generated policy differs from the fixed owner fixture")
		}
		owner, err = prepareOwnerNFSRuntime(ctx, b.inputs)
		if err != nil {
			return err
		}
		if duplicate, err := nfsowner.NewManagedLinuxQEMU(ctx, b.inputs, nfsowner.LinuxServiceGrants{}); duplicate != nil || !errors.Is(err, nfsowner.ErrState) {
			return errors.New("NFS runtime took the same retained inputs twice")
		}
		b.phase = "start"
		if err := owner.Start(ctx); err != nil {
			return fmt.Errorf("owner-start: %w", err)
		}
		if err := nfsowner.CheckManagedRefusalsQEMU(ctx, owner); err != nil {
			return err
		}
		if !errors.Is(b.inputs.Close(), nfsowner.ErrState) || !errors.Is(b.inputs.Check(ctx, candidate), nfsowner.ErrState) {
			return errors.New("running NFS input ownership could be bypassed")
		}
		b.phase = "client"
		if err := os.Mkdir(ownerNFSClient, 0700); err != nil {
			return err
		}
		if err := b.command(ctx, "/bin/mount", "-t", "nfs", "-o", "rw,vers=3,proto=tcp,mountproto=tcp,nolock,soft,timeo=5,retrans=1", "127.0.0.1:"+ownerNFSRoot, ownerNFSClient); err != nil {
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
		if err := nfsowner.CheckManagedTablesQEMU(ctx, ownerNFSRoot, "127.0.0.1"); err != nil {
			return err
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
		previousTCPPeer, err := stopOwnerWithServerTimeWaitQEMU(ctx, owner.Stop)
		if err != nil {
			return fmt.Errorf("owner-stop: %w", err)
		}
		if b.policyLease.Verify(ctx) != nil || b.management.exchange(ctx, &next, 503) != nil {
			return errors.New("NFS stop released desired-policy authority before close")
		}
		b.phase = "close"
		if err := owner.Close(ctx); err != nil {
			return err
		}
		if !errors.Is(b.inputs.Check(ctx, candidate), nfsowner.ErrState) {
			return errors.New("closed NFS input preparation admitted its old candidate")
		}
		if err := b.releaseBorrowedInputs(ctx); err != nil {
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
		b.phase = "policy-readback-after-close"
		updated, err := b.policyOwner.Snapshot(ctx)
		if err != nil || updated.Revision != next.Revision || len(updated.FileServices.NFS.Exports) != 1 ||
			len(updated.FileServices.NFS.Exports[0].Clients) != 1 || updated.FileServices.NFS.Exports[0].Clients[0].Access != "rw" {
			return errors.New("desired-policy update after NFS close was not observed")
		}
		b.phase = "policy-reapply"
		if err := b.reapplySavedPolicy(ctx, owner, previousTCPPeer); err != nil {
			return err
		}
		b.phase = "policy-verify-after-reapply"
		if err := b.management.exchange(ctx, nil, 200); err != nil {
			return err
		}
		b.phase = "policy-close-management"
		if err := b.management.Close(); err != nil {
			return err
		}
		b.phase = "policy-data-cleanup"
		for _, p := range []string{ownerNFSRoot + "/updated", ownerNFSRoot + "/marker", ownerNFSRoot} {
			if err := os.Remove(p); err != nil {
				return err
			}
		}
		b.phase = "policy-close-identity"
		if err := b.identity.Close(); err != nil {
			return err
		}
		b.phase = "policy-close-authority"
		if err := b.policyOwner.Close(); err != nil {
			return err
		}
		// Diagnostic only after verified consumer teardown, never boot admission.
		b.phase = "policy-observe-ordered-receipt"
		b.policyEvidence, err = revisionstore.OpenNASEvidenceAuthority(ctx, ownerNFSPolicy, ownerNFSInstallation)
		if err != nil {
			return err
		}
		evidence, observeErr := b.policyEvidence.Observe(ctx)
		closeErr := b.policyEvidence.Close()
		if errors.Join(observeErr, closeErr) != nil || evidence.Kind != naspolicyevidence.MatchingLocalRecords || evidence.Pending || evidence.Roles != 5 {
			return errors.New("NFS ordered-policy receipt differs after verified shutdown")
		}
		b.policyEvidence = nil
		return nil
	})
	if err != nil {
		return err
	}
	afterTables, err := qemuNFSDefaultTables()
	if err != nil || afterTables != defaultTables {
		return errors.Join(errors.New("managed NFS changed the default nfs-utils tables"), err)
	}
	if err := removeStateConfig(); err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_OWNER_ACTIVATION_READY original_identity=true original_storage=true generated_policy=true owner_running=true kernel_backend=true activation=true read=true write=EROFS stopped=true sources_released=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_LINUX_OWNER_READY input_owner=exclusive duplicate=refused live_close=refused borrowed_claims=retained shutdown=verified scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_LINUX_KERNEL_READY grants=retained swapped_namespace=refused lock=exclusive lifetimes=2 threads=verified scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_MANAGED_RPC_READY code=retained order=verified live_close=refused helpers=reaped lifetimes=2 scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_MOUNT_TRANSPORT_READY profile=tcp port=20048 listener=owned occupied_udp=refused teardown=verified lifetimes=2 scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_MANAGED_RUNTIME_READY grants=retained rollback=verified lifetimes=2 teardown=verified scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_PRIVATE_STATE_READY etab=private rmtab=private defaults=unchanged stale=refused lifetimes=2 cleanup=verified scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_MANAGED_EXPORTS_READY candidate=retained readback=exact live_close=refused withdrawal=verified lifetimes=2 scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_POLICY_ACTIVATION_READY original_policy=true revision=1 update_while_running=busy active_bytes_unchanged=true update_after_close=committed released_after_stop=true kernel_backend=true activation=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_POLICY_REAPPLY_READY revision=2 lifetimes=2 original_policy=true fresh_claims=true read=true write=sync-verified uid_gid=verified old_owner=inert teardown=clean kernel_backend=true activation=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_OWNER_TCP_REBIND_READY previous_server_time_wait=true live_duplicate_refused=true reapply=true teardown=clean scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_ORDERED_POLICY_READY original_owner=true ordered_writer=true receipt=verified reactivation=verified kernel_backend=true activation=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NAS_POLICY_HTTP_READY original_owner=true protocols=smb,nfs,iscsi busy_while_running=true commit_after_close=true revision=2 nfs_reapplied=true scope=qemu-loopback-only")
	if err := exerciseQEMUNASPolicyRPC(); err != nil {
		return err
	}
	return exerciseQEMUNASPolicyMainProcess()
}

type qemuNFSTable struct {
	found bool
	data  string
}

func qemuNFSDefaultTables() ([2]qemuNFSTable, error) {
	var tables [2]qemuNFSTable
	for i, path := range []string{"/var/lib/nfs/etab", "/var/lib/nfs/rmtab"} {
		data, err := os.ReadFile(path)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return tables, err
		}
		tables[i] = qemuNFSTable{found: err == nil, data: string(data)}
	}
	return tables, nil
}

func (b *ownerNFSQEMU) prepareFixtureSources(ctx context.Context, network, access string) error {
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
		Clients: []nfsconfig.Client{{Network: network, Access: access, Squash: "all", AnonymousUID: b.uid, AnonymousGID: b.gid, Security: "sys"}}}}
	document := naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: 1, FileServices: config,
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: 1, VolumeRevision: 1,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
	if err := b.retainPolicy(ctx, document); err != nil {
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
	if err := os.Mkdir(ownerNFSRoot, 0700); err != nil {
		return err
	}
	if err := os.Chown(ownerNFSRoot, int(b.uid), int(b.gid)); err != nil {
		return err
	}
	if err := os.WriteFile(ownerNFSRoot+"/marker", []byte("owner-derived-nfs\n"), 0644); err != nil {
		return err
	}
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
	confirmed, err := json.Marshal(document)
	if err != nil {
		return err
	}
	// Fixed fresh disposable provisioning; observed/legacy bytes are not adopted.
	if err := writeQEMUStateFixture(ownerNFSPolicy+"/nas-evidence.json", []byte(`{"format":"phantowd-nas-evidence-container","schema_version":1,"installation_id":"`+ownerNFSInstallation+`"}`)); err != nil {
		return err
	}
	b.policyOwner, err = naspolicystore.OpenConfirmedOwner(ctx, ownerNFSPolicy, ownerNFSInstallation, confirmed)
	if err != nil {
		return err
	}
	b.policyLease, err = b.policyOwner.Acquire(ctx, document.Revision)
	return err
}

func verifyOwnerNFSClientAbsent(ctx context.Context) error {
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil || strings.Contains(string(mounts), " "+ownerNFSClient+" ") {
		return errors.New("NFS client absence uncertain")
	}
	return ctx.Err()
}

func withQEMUNFSGrants(address netip.Addr, quiescent func(context.Context) error,
	use func(nfsowner.LinuxServiceGrants) (*nfsowner.Owner, error)) (_ *nfsowner.Owner, result error) {
	// The caller established the disposable guest and synthetic disk. Acquire
	// the originals from this thread and close them before the service starts.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	grants := nfsowner.LinuxServiceGrants{
		Address: address, Quiescent: quiescent,
	}
	for _, entry := range []struct {
		path string
		file **os.File
	}{
		{"/proc/fs/nfsd", &grants.NFSD},
		{"/proc/thread-self/ns/net", &grants.Network},
		{"/proc/thread-self/ns/mnt", &grants.MountNamespace},
		{"/usr/sbin/exportfs", &grants.ExportFS},
		{"/usr/sbin/rpcbind", &grants.RPCBind},
		{"/usr/sbin/rpc.mountd", &grants.Mountd},
		{"/usr/bin/rpcinfo", &grants.Info},
	} {
		file, err := os.Open(entry.path)
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, file.Close()) }()
		*entry.file = file
	}
	return use(grants)
}

func prepareOwnerNFSRuntime(ctx context.Context, inputs *nfsowner.RetainedInputs) (*nfsowner.Owner, error) {
	return withQEMUNFSGrants(netip.AddrFrom4([4]byte{127, 0, 0, 1}), verifyOwnerNFSClientAbsent, func(grants nfsowner.LinuxServiceGrants) (_ *nfsowner.Owner, result error) {

		wrong := grants
		wrong.Network, wrong.MountNamespace = wrong.MountNamespace, wrong.Network
		if owner, err := nfsowner.NewManagedLinuxQEMU(ctx, inputs, wrong); owner != nil || !errors.Is(err, nfskernel.ErrRefused) || constructionreview.Contains(err) {
			return owner, errors.Join(errors.New("managed NFSD did not cleanly refuse swapped namespace grants"), err)
		}
		if err := nfsowner.CheckStaleManagedStateQEMU(ctx, inputs, grants); err != nil {
			return nil, err
		}
		incomplete := grants
		incomplete.Mountd = nil
		if owner, err := nfsowner.NewManagedLinuxQEMU(ctx, inputs, incomplete); owner != nil || err == nil || constructionreview.Contains(err) {
			return owner, errors.Join(errors.New("managed construction did not unwind a refused mountd grant"), err)
		}

		owner, err := nfsowner.NewManagedLinuxQEMU(ctx, inputs, grants)
		if err != nil {
			return owner, err
		}
		lock, err := os.OpenFile("/run/.phantowd-nfs-kernel.lock", os.O_WRONLY, 0)
		if err != nil {
			return owner, err
		}
		defer func() { result = errors.Join(result, lock.Close()) }()
		if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
			return owner, errors.New("Linux NFSD admitted another lock claimant")
		}
		return owner, nfsowner.CheckManagedRefusalsQEMU(ctx, owner)
	})
}

func (b *ownerNFSQEMU) releaseBorrowedInputs(ctx context.Context) error {
	if err := nfsowner.CheckManagedStateReapedQEMU(); err != nil {
		return err
	}
	if err := os.Remove(ownerNFSClient); err != nil {
		return err
	}
	return b.releaseFixtureClaims(ctx)
}

func (b *ownerNFSQEMU) releaseFixtureClaims(ctx context.Context) error {
	// The parent owns both claims through verified service and storage close.
	if err := errors.Join(b.identityLease.Verify(ctx), b.policyLease.Verify(ctx)); err != nil {
		return err
	}
	if err := b.identityLease.Release(); err != nil {
		return err
	}
	return b.policyLease.Release()
}

func (b *ownerNFSQEMU) command(ctx context.Context, path string, args ...string) error {
	cmd := exec.CommandContext(ctx, path, args...)
	cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("NFS command %s: %w", path, err)
	}
	return nil
}
