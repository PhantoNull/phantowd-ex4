//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package naspolicystore stores desired SMB/NFS/iSCSI as one revision.
// State provisioning, migration, credentials and activation remain separate.
package naspolicystore

import (
	"context"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
)

type Store = revisionstore.Store[naspolicy.Config]
type Owner = revisionstore.OwnedStore[naspolicy.Config]
type Lease = revisionstore.PolicyLease[naspolicy.Config]
type BootstrapAuthority = revisionstore.BootstrapAuthority[naspolicy.Config]
type OwnerBootstrap = revisionstore.NASOwnerBootstrap

var (
	ErrNotInitialized = revisionstore.ErrNotInitialized
	ErrConflict       = revisionstore.ErrConflict
	ErrInvalid        = revisionstore.ErrInvalid
	ErrUnsafe         = revisionstore.ErrUnsafe
	ErrBusy           = revisionstore.ErrBusy
	ErrUncertain      = revisionstore.ErrUncertain
	ErrReview         = revisionstore.ErrReview
	ErrClosed         = revisionstore.ErrClosed
)

// Open requires a separately provisioned private directory and holds its
// exclusive lock. No independent SMB/NFS/iSCSI writers or implicit import.
func Open(directory string) (*Store, error) {
	return revisionstore.OpenWithCodec(directory, policyCodec())
}

// OpenOwner requires initialized state and supplies private retained policy
// leases. It is not product boot wiring, migration or service authority.
func OpenOwner(directory string) (*Owner, error) {
	return revisionstore.OpenOwnedWithCodec(directory, policyCodec())
}

// OpenConfirmedOwner uses ordered evidence under the existing concrete leases.
// Trusted parents must separately confirm base bytes and consumer exclusion;
// this does not provision state or authorize product boot/reconciliation.
func OpenConfirmedOwner(ctx context.Context, directory, installation string, confirmed []byte) (*Owner, error) {
	return revisionstore.OpenConfirmedNASOwner(ctx, directory, installation, confirmed)
}

// OpenOwnerBootstrap is a distinct trusted-parent capability, never a conversion
// of a read-only observer. Confirm requires independent bytes and consumer exclusion.
func OpenOwnerBootstrap(ctx context.Context, directory, installation string) (*OwnerBootstrap, error) {
	return revisionstore.OpenNASOwnerBootstrap(ctx, directory, installation)
}

// ObserveBootstrap uses only this package's fixed names/schema. The redacted
// observation is not initialization, recovery, a policy lease or permission
// to open/activate an Owner later. No HTTP or product startup is wired here.
func ObserveBootstrap(ctx context.Context, directory string) (revisionstore.BootstrapObservation, error) {
	return revisionstore.ObserveBootstrapWithCodec(ctx, directory, policyCodec())
}

// OpenBootstrapAuthority retains the fixed NAS read-only directory/codec/watch
// lifetime. It does not grant Owner admission, leases, mutation or recovery.
func OpenBootstrapAuthority(ctx context.Context, directory string) (*BootstrapAuthority, error) {
	return revisionstore.OpenBootstrapAuthorityWithCodec(ctx, directory, policyCodec())
}

func policyCodec() revisionstore.Codec[naspolicy.Config] {
	return revisionstore.Codec[naspolicy.Config]{
		CurrentName: "nas-services.json", PendingName: ".nas-services.pending",
		MaxBytes: naspolicy.MaxInputBytes, Decode: naspolicy.Decode, Validate: naspolicy.Config.Validate,
		Revision: func(c naspolicy.Config) uint64 { return c.Revision },
		ValidateTransition: func(current, next naspolicy.Config) error {
			return fileservice.ValidateRetainedNFSBindings(current.FileServices, next.FileServices)
		},
	}
}
