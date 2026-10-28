//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"strings"
	"syscall"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

// A second explicit lifetime only after verified stop/close, never a retry.
// The parent retains the original policy/identity/storage Owners and dataset.
func (parent *ownerNFSQEMU) reapplySavedPolicy(ctx context.Context, previous *nfsowner.Owner) (result error) {
	b := &ownerNFSQEMU{storage: parent.storage, identity: parent.identity, policyOwner: parent.policyOwner,
		uid: parent.uid, gid: parent.gid, access: "rw", phase: "revision2-prepare"}
	var owner *nfsowner.Owner
	defer func() {
		if result != nil {
			result = &ownerNFSReview{backend: b, owner: owner, cause: result, contextDone: ctx.Err() != nil}
		}
	}()
	var err error
	b.policyLease, err = b.policyOwner.Acquire(ctx, 2)
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
	plan, err := fileserviceplan.BuildFromLeasedNASOwners(ctx, b.policyLease, 0, b.identityLease, b.storage)
	if err != nil {
		return err
	}
	candidate, err := plan.NFSv3TCPCandidate()
	if err != nil {
		return err
	}
	b.storageLease, _, err = b.storage.Acquire(ctx)
	if err != nil {
		return err
	}
	b.roots, err = nfsowner.NewExportRootsQEMU(ctx, candidate, b.storageLease)
	if err != nil {
		return err
	}
	enabled, table, roots, err := candidate.Documents()
	lines := strings.Split(strings.TrimSpace(table), "\n")
	if err != nil || !enabled || len(roots) != 1 || len(lines) != 2 || !matchesQEMUOwnerMountedExportAccess(lines[1], ownerNFSRoot, b.uid, b.gid, "rw") {
		return errors.New("saved NFS revision did not derive the fixed read-write export")
	}
	b.options = strings.TrimSuffix(strings.TrimPrefix(strings.Fields(lines[1])[1], "127.0.0.1/32("), ")")
	before, err := os.ReadFile(ownerNFSPolicy + "/nas-services.json")
	if err != nil {
		return err
	}
	owner, err = nfsowner.NewQEMU(candidate, b)
	if err != nil {
		return err
	}
	b.phase = "revision2-start"
	if err := owner.Start(ctx); err != nil {
		return err
	}
	// The old Owner is closed; its calls cannot touch the new backend.
	for _, call := range []func(context.Context) error{previous.Start, previous.Stop, previous.Check} {
		if !errors.Is(call(ctx), nfsowner.ErrState) {
			return errors.New("closed NFS Owner admitted an operation")
		}
	}
	if err := previous.Close(ctx); err != nil {
		return err
	}
	if state, err := previous.Observe(); err != nil || state != nfsowner.Closed {
		return errors.New("previous NFS Owner is no longer closed")
	}
	b.phase = "revision2-client"
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
		return errors.New("saved-policy client is not the exact NFSv3/TCP mount")
	}
	data, err := os.ReadFile(ownerNFSClient + "/marker")
	if err != nil || string(data) != "owner-derived-nfs\n" {
		return errors.New("saved-policy client lost the previous dataset")
	}
	const payload = "saved-policy-nfs-revision2\n"
	f, err := os.OpenFile(ownerNFSClient+"/updated", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	n, writeErr := f.WriteString(payload)
	syncErr := f.Sync()
	closeErr := f.Close()
	if err := errors.Join(writeErr, syncErr, closeErr); err != nil {
		return err
	}
	if n != len(payload) {
		return errors.New("saved-policy NFS write was partial")
	}
	for _, path := range []string{ownerNFSClient + "/updated", ownerNFSRoot + "/updated"} {
		data, err := os.ReadFile(path)
		if err != nil || string(data) != payload {
			return errors.New("saved-policy NFS write bytes differ")
		}
		info, err := os.Stat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !ok || stat.Uid != b.uid || stat.Gid != b.gid {
			return errors.New("saved-policy NFS write has unexpected ownership")
		}
	}
	if err := owner.Check(ctx); err != nil {
		return err
	}
	b.phase = "revision2-stop"
	if err := b.command(ctx, "/bin/umount", ownerNFSClient); err != nil {
		return err
	}
	if err := owner.Stop(ctx); err != nil {
		return err
	}
	b.phase = "revision2-close"
	if err := owner.Close(ctx); err != nil {
		return err
	}
	if !errors.Is(b.policyLease.Verify(ctx), naspolicystore.ErrClosed) {
		return errors.New("second NFS closure retained a policy claim")
	}
	after, err := os.ReadFile(ownerNFSPolicy + "/nas-services.json")
	if err != nil || !bytes.Equal(before, after) {
		return errors.New("saved-policy activation changed the stored document")
	}
	return nil
}
