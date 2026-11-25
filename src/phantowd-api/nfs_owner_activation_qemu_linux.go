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
	identity        *identityowner.Owner
	identityLease   *identityowner.FileServiceLease
	storage         *mountowner.MountedVolumeSet
	inputs          *nfsowner.RetainedInputs
	policySeed      *naspolicystore.Store
	policyOwner     *naspolicystore.Owner
	policyLease     *naspolicystore.Lease
	policyEvidence  *revisionstore.NASEvidenceAuthority
	management      *qemuNASPolicyHTTP
	kernel          *nfskernel.Controller
	rpc             *nfsowner.RPC
	exports         *nfsowner.Exports
	phase           string
	uid, gid        uint32
	kernelAttempted bool
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
	err := mountowner.WithQEMUMountedSet(smbFixtureAnchor, func(set *mountowner.MountedVolumeSet) (result error) {
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
		if err := os.Mkdir(ownerNFSRoot, 0700); err != nil {
			return err
		}
		if err := os.Chown(ownerNFSRoot, int(b.uid), int(b.gid)); err != nil {
			return err
		}
		if err := os.WriteFile(ownerNFSRoot+"/marker", []byte("owner-derived-nfs\n"), 0644); err != nil {
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
		owner, err = nfsowner.NewLinux(b.inputs, b)
		if err != nil {
			return err
		}
		if duplicate, err := nfsowner.NewLinux(b.inputs, b); duplicate != nil || !errors.Is(err, nfsowner.ErrState) {
			return errors.New("NFS runtime took the same retained inputs twice")
		}
		b.phase = "start"
		if err := owner.Start(ctx); err != nil {
			return fmt.Errorf("owner-start: %w", err)
		}
		if !errors.Is(b.inputs.Close(), nfsowner.ErrState) || !errors.Is(b.inputs.Check(ctx, candidate), nfsowner.ErrState) {
			return errors.New("running NFS input ownership could be bypassed")
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
	fmt.Println("PHANTOWD_NFS_OWNER_ACTIVATION_READY original_identity=true original_storage=true generated_policy=true owner_running=true kernel_backend=true activation=true read=true write=EROFS stopped=true sources_released=true scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_LINUX_OWNER_READY input_owner=exclusive duplicate=refused live_close=refused borrowed_claims=retained shutdown=verified scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_LINUX_KERNEL_READY grants=retained swapped_namespace=refused lock=exclusive lifetimes=2 threads=verified scope=qemu-loopback-only")
	fmt.Println("PHANTOWD_NFS_MANAGED_RPC_READY code=retained order=verified live_close=refused helpers=reaped lifetimes=2 scope=qemu-loopback-only")
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

func (b *ownerNFSQEMU) VerifyStopped(ctx context.Context) error {
	if b.exports != nil {
		if err := b.exports.VerifyEmpty(ctx); err != nil {
			return err
		}
	}
	if b.rpc != nil {
		if err := b.rpc.VerifyStopped(ctx); err != nil {
			return err
		}
	}
	mounts, err := os.ReadFile("/proc/mounts")
	if err != nil || strings.Contains(string(mounts), " "+ownerNFSClient+" ") {
		return errors.New("NFS client absence uncertain")
	}
	if b.kernel != nil {
		if !b.kernelAttempted {
			return b.kernel.CheckPrepared(ctx)
		}
		return b.kernel.CheckStopped(ctx)
	}
	threads, e1 := os.ReadFile("/proc/fs/nfsd/threads")
	versions, e2 := os.ReadFile("/proc/fs/nfsd/versions")
	ports, e3 := os.ReadFile("/proc/fs/nfsd/portlist")
	return errors.Join(e1, e2, e3, nfskernel.ValidateProfileQEMU(threads, versions, ports, false))
}

func (b *ownerNFSQEMU) Start(ctx context.Context) error {
	phase := b.phase
	b.phase = phase + "-kernel-open"
	var err error
	b.kernel, err = openOwnerNFSKernel(ctx)
	if err != nil {
		return err
	}
	b.phase = phase + "-export-admission"
	b.exports, err = openOwnerNFSExports(ctx, b)
	if err != nil {
		return err
	}
	if err := b.exports.VerifyEmpty(ctx); err != nil {
		return err
	}
	b.phase = phase + "-rpc-admission"
	b.rpc, err = openOwnerNFSRPC(ctx, b.kernel)
	if err != nil {
		return err
	}
	if !errors.Is(b.rpc.StartMountd(ctx), nfsowner.ErrState) {
		return errors.New("managed mountd accepted startup before rpcbind")
	}
	b.phase = phase + "-rpcbind-start"
	if err := b.rpc.StartBinder(ctx); err != nil {
		return err
	}
	b.phase = phase + "-kernel-start"
	b.kernelAttempted = true
	if err := b.kernel.Start(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "PHANTOWD_NFS_OWNER_KERNEL_START_REFUSED owner_phase=%s cause=%v\n", b.phase, err)
		return err
	}
	b.phase = phase + "-mountd-start"
	if err := b.rpc.StartMountd(ctx); err != nil {
		return err
	}
	if !errors.Is(b.rpc.Close(ctx), nfsowner.ErrState) {
		return errors.New("managed RPC pins were released while the helpers ran")
	}
	b.phase = phase + "-export"
	if err := b.exports.Publish(ctx); err != nil {
		return err
	}
	if !errors.Is(b.exports.Close(ctx), nfsowner.ErrState) {
		return errors.New("managed export grants were released while published")
	}
	b.phase = phase + "-verify-ready"
	return nil
}

func openOwnerNFSExports(ctx context.Context, b *ownerNFSQEMU) (_ *nfsowner.Exports, result error) {
	file, err := os.Open("/usr/sbin/exportfs")
	if err != nil {
		return nil, err
	}
	defer func() { result = errors.Join(result, file.Close()) }()
	return nfsowner.NewExports(ctx, b.inputs, b.kernel, netip.AddrFrom4([4]byte{127, 0, 0, 1}), file)
}

func openOwnerNFSRPC(ctx context.Context, kernel *nfskernel.Controller) (_ *nfsowner.RPC, result error) {
	var grants [3]*os.File
	for i, path := range []string{"/usr/sbin/rpcbind", "/usr/sbin/rpc.mountd", "/usr/bin/rpcinfo"} {
		grant, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, grant.Close()) }()
		grants[i] = grant
	}
	return nfsowner.NewRPC(ctx, kernel, netip.AddrFrom4([4]byte{127, 0, 0, 1}), grants[0], grants[1], grants[2])
}

func openOwnerNFSKernel(ctx context.Context) (_ *nfskernel.Controller, result error) {
	// The caller already established the disposable Versatile guest and data
	// disk. These grants come from the same current thread and NFSD mount.
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var grants [3]*os.File
	for i, path := range []string{"/proc/fs/nfsd", "/proc/thread-self/ns/net", "/proc/thread-self/ns/mnt"} {
		grant, err := os.Open(path)
		if err != nil {
			return nil, err
		}
		defer func() { result = errors.Join(result, grant.Close()) }()
		grants[i] = grant
	}
	address := netip.AddrFrom4([4]byte{127, 0, 0, 1})
	if controller, err := nfskernel.OpenLinux(ctx, grants[0], grants[2], grants[1], address); controller != nil || !errors.Is(err, nfskernel.ErrRefused) {
		return controller, errors.New("Linux NFSD accepted swapped namespace grants")
	}
	controller, err := nfskernel.OpenLinux(ctx, grants[0], grants[1], grants[2], address)
	if err != nil {
		return controller, err
	}
	lock, err := os.OpenFile("/run/.phantowd-nfs-kernel.lock", os.O_WRONLY, 0)
	if err != nil {
		return controller, err
	}
	defer func() { result = errors.Join(result, lock.Close()) }()
	if err := unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		return controller, errors.New("Linux NFSD admitted another lock claimant")
	}
	return controller, nil
}

func (b *ownerNFSQEMU) VerifyReady(ctx context.Context) error {
	if err := b.kernel.CheckRunning(ctx); err != nil {
		return err
	}
	if err := b.rpc.VerifyReady(ctx); err != nil {
		return err
	}
	return b.exports.CheckPublished(ctx)
}

func (b *ownerNFSQEMU) Stop(ctx context.Context) error {
	if b.kernelAttempted {
		if err := b.kernel.Stop(ctx); err != nil {
			return err
		}
	}
	if b.exports != nil {
		if err := b.exports.Withdraw(ctx); err != nil {
			return err
		}
	}
	if b.rpc != nil {
		return b.rpc.Stop(ctx)
	}
	return nil
}

func (b *ownerNFSQEMU) Close(ctx context.Context) error {
	if b.exports != nil {
		if err := b.exports.Close(ctx); err != nil {
			return err
		}
	}
	if b.rpc != nil {
		if err := b.rpc.Close(ctx); err != nil {
			return err
		}
	}
	if b.kernel != nil {
		if err := b.kernel.Close(ctx); err != nil {
			return err
		}
	}
	return os.Remove(ownerNFSClient)
}

func (b *ownerNFSQEMU) releaseBorrowedInputs(ctx context.Context) error {
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
