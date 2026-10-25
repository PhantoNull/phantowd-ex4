//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfskernel"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
)

const ownerNFSRoot = "/srv/phantowd/volumes/qemu-plan/nfs-owner"
const ownerNFSClient = "/run/phantowd-nfs-owner-client"

// Fixed disposable-guest composition only. These are original retained inputs,
type ownerNFSQEMU struct {
	identity      *identityowner.Owner
	identityLease *identityowner.FileServiceLease
	storage       *mountowner.MountedVolumeSet
	storageLease  *mountowner.MountedVolumeSetLease
	roots         *nfsowner.ExportRootsQEMU
	config        fileservice.Config
	kernel        *nfskernel.ControllerQEMU
	helpers       [2]*ownerNFSChild
	options       string
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

func (*ownerNFSReview) Error() string   { return "NFS activation retains original sources for review" }
func (r *ownerNFSReview) Unwrap() error { return r.cause }

func runQEMUNFSOwnerActivation() error {
	if err := guardQEMUDataVolume(); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	err := mountowner.WithQEMUMountedSet(smbFixtureAnchor, func(set *mountowner.MountedVolumeSet) (result error) {
		b := &ownerNFSQEMU{storage: set}
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
		b.config = emptyQEMUFileServiceConfig()
		b.config.Shares.Volumes = []shareconfig.Volume{{ID: qemuPlannerVolumeID, FilesystemUUID: qemuNFSVolumeUUID}}
		b.config.NFS.Exports = []nfsconfig.Export{{ID: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff", VolumeID: qemuPlannerVolumeID, RelativePath: "nfs-owner",
			Clients: []nfsconfig.Client{{Network: "127.0.0.1/32", Access: "ro", Squash: "all", AnonymousUID: b.uid, AnonymousGID: b.gid, Security: "sys"}}}}
		plan, err := fileserviceplan.BuildFromOwners(ctx, b.config, 0, b.identity, set)
		if err != nil {
			return err
		}
		candidate, err := plan.NFSv3TCPCandidate()
		if err != nil {
			return err
		}
		b.identityLease, err = b.identity.RetainFileServiceSnapshot(ctx, plan.Freshness().IdentityFingerprint)
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
		if err := owner.Start(ctx); err != nil {
			return fmt.Errorf("owner-start: %w", err)
		}
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
		if err := owner.Check(ctx); err != nil {
			return fmt.Errorf("owner-check: %w", err)
		}
		if err := b.command(ctx, "/bin/umount", ownerNFSClient); err != nil {
			return err
		}
		if err := owner.Stop(ctx); err != nil {
			return fmt.Errorf("owner-stop: %w", err)
		}
		return owner.Close(ctx)
	})
	if err != nil {
		return err
	}
	fmt.Println("PHANTOWD_NFS_OWNER_ACTIVATION_READY original_identity=true original_storage=true generated_policy=true owner_running=true kernel_backend=true activation=true read=true write=EROFS stopped=true sources_released=true scope=qemu-loopback-only")
	return nil
}

func (b *ownerNFSQEMU) CheckInputs(ctx context.Context, candidate fileserviceplan.NFSv3Candidate) error {
	plan, err := fileserviceplan.BuildFromRetainedOwners(ctx, b.config, 0, b.identityLease, b.storage)
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
	if err != nil || len(lines) != 1 || !matchesQEMUOwnerMountedExport(lines[0], ownerNFSRoot, b.uid, b.gid) {
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
	for _, p := range []string{ownerNFSRoot + "/marker", ownerNFSRoot, ownerNFSClient} {
		if err := os.Remove(p); err != nil {
			return err
		}
	}
	for _, close := range []func() error{b.storageLease.Close, b.identityLease.Release, b.identity.Close} {
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
