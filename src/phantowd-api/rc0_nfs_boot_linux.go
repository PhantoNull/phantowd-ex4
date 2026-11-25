// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"net/netip"
	"sync/atomic"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/nfsowner"
)

type rc0NFSApproval struct {
	Address      netip.Addr `json:"address"`
	IngressIndex int        `json:"ingress_index"`
}

func (a rc0NFSApproval) valid() bool {
	return a.Address.Is4() && a.Address.IsGlobalUnicast() && a.IngressIndex > 0
}

// The private stop socket admits one request to the original supervisor.
// Drain confirmation is volatile and accepted only together with that stop.
type rc0BootStopAuthority struct {
	nfs, ready, stopping atomic.Bool
}

func (a *rc0BootStopAuthority) accept(request byte) bool {
	if !a.ready.Load() {
		return false
	}
	expected := byte(rc0StopRequest)
	if a.nfs.Load() {
		expected = rc0DrainedStopRequest
	}
	return request == expected && a.stopping.CompareAndSwap(false, true)
}

func (a *rc0BootStopAuthority) quiescent(ctx context.Context) error {
	if !a.nfs.Load() || !a.stopping.Load() {
		return errRC0Review
	}
	return ctx.Err()
}

func startRC0NFS(ctx context.Context, control *rc0BootStopAuthority, approval *rc0StorageApproval,
	policy *naspolicystore.Owner, identity *identityowner.Owner, storage *registeredStorage) (*registeredNFS, error) {
	if approval == nil || approval.NFS == nil {
		return nil, nil
	}
	if control == nil || identity == nil || storage == nil {
		return nil, errRC0Review
	}
	document, err := policy.Snapshot(ctx)
	if err != nil {
		return nil, err
	}
	if len(document.FileServices.NFS.Exports) == 0 {
		return nil, errRC0Review
	}
	nfs, err := prepareLocalRegisteredNFS(ctx, registeredNFSGrants{
		policy: policy, identity: identity, storage: storage, desired: document.Revision,
		runtime: nfsowner.LinuxServiceGrants{
			Address: approval.NFS.Address, IngressIndex: approval.NFS.IngressIndex, Quiescent: control.quiescent,
		},
	})
	if err != nil {
		return nil, err
	}
	// Protect a partial start as soon as publication becomes possible.
	control.nfs.Store(true)
	return nfs, nfs.Start(ctx)
}
