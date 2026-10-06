//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"errors"
	"os"
	"slices"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

// NativeBackendQEMU fixes the retained runtime at construction, before binding
// to identityowner.OpenWithSMBBackend. It delegates the existing journal-facing
// command/observation/password logic; it adds no per-operation backend choice.
// The runtime owns code/config/state and can be released only after workers
// settle. This guarded fixture is not product startup or an HTTP surface.
type NativeBackendQEMU struct {
	inner   *Backend
	runtime *runtimebundle.NativeSambaRuntimeQEMU
	mu      sync.RWMutex
}

func NewNativeBackendQEMU(ctx context.Context, runtime *runtimebundle.NativeSambaRuntimeQEMU) (*NativeBackendQEMU, error) {
	if ctx == nil || runtime == nil {
		return nil, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	config, err := openConfig(runtimebundle.NativeSambaConfigQEMU)
	if err != nil {
		return nil, ErrInvalid
	}
	if err := runtime.AcceptConfigurationQEMU(ctx, config); err != nil {
		return nil, errors.Join(err, config.Close())
	}
	output, err := runtime.ExecuteQEMU(ctx, processowner.NativeSambaCheckQEMU, "", nil)
	clear(output)
	if err != nil {
		return nil, errors.Join(err, config.Close())
	}
	return &NativeBackendQEMU{
		inner: &Backend{config: config, runner: &nativeRunnerQEMU{runtime: runtime}}, runtime: runtime,
	}, nil
}

type nativeRunnerQEMU struct {
	runtime *runtimebundle.NativeSambaRuntimeQEMU
}

func (r *nativeRunnerQEMU) Run(ctx context.Context, executable string, args []string, config *os.File, stdin []byte, capture bool) ([]byte, error) {
	if r == nil || r.runtime == nil || ctx == nil || config == nil {
		return nil, ErrInvalid
	}
	var operation processowner.NativeSambaOperationQEMU
	name := ""
	switch {
	case executable == pdbeditPath && slices.Equal(args, []string{"-L", "-v", "-s", configArgument}):
		operation = processowner.NativeSambaListQEMU
	case executable == smbstatusPath && slices.Equal(args, []string{"-j", "-s", configArgument}):
		operation = processowner.NativeSambaStatusQEMU
	case executable == smbcontrolPath && len(args) == 5 && slices.Equal(args[:4], []string{"-s", configArgument, "smbd", "logoff-user"}):
		operation, name = processowner.NativeSambaRevokeQEMU, args[4]
	case executable == smbpasswdPath && len(args) == 5 && slices.Equal(args[:4], []string{"-a", "-d", "-c", configArgument}):
		operation, name = processowner.NativeSambaCreateQEMU, args[4]
	case executable == smbpasswdPath && len(args) == 5 && slices.Equal(args[:4], []string{"-s", "--set-password-disabled", "-c", configArgument}):
		operation, name = processowner.NativeSambaPasswordQEMU, args[4]
	case executable == smbpasswdPath && len(args) == 4 && slices.Equal(args[1:3], []string{"-c", configArgument}):
		switch args[0] {
		case "-e":
			operation = processowner.NativeSambaEnableQEMU
		case "-d":
			operation = processowner.NativeSambaDisableQEMU
		}
		name = args[3]
	}
	if operation == 0 {
		return nil, ErrInvalid
	}
	if err := r.runtime.AcceptConfigurationQEMU(ctx, config); err != nil {
		return nil, err
	}
	output, err := r.runtime.ExecuteQEMU(ctx, operation, name, stdin)
	if err != nil || !capture {
		clear(output)
		return nil, err
	}
	return output, nil
}

func nativeFixtureAccountQEMU(account serviceaccounts.Account) bool {
	return account.GID == account.UID && ((account.Name == "qpmanaged" && account.UID == 2000) ||
		(account.Name == "qpsecond" && account.UID == 2001))
}

func (b *NativeBackendQEMU) Observe(ctx context.Context, account serviceaccounts.Account) (smbprovision.Observation, error) {
	observations, err := b.ObserveAccounts(ctx, []serviceaccounts.Account{account})
	if err != nil {
		return smbprovision.Observation{}, err
	}
	return observations[0], nil
}

func (b *NativeBackendQEMU) ObserveAccounts(ctx context.Context, accounts []serviceaccounts.Account) ([]smbprovision.Observation, error) {
	if b == nil {
		return nil, ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.inner == nil {
		return nil, ErrInvalid
	}
	for _, account := range accounts {
		if !nativeFixtureAccountQEMU(account) {
			return nil, ErrInvalid
		}
	}
	return b.inner.ObserveAccounts(ctx, accounts)
}

func (b *NativeBackendQEMU) CreateDisabled(ctx context.Context, account serviceaccounts.Account) error {
	if b == nil || !nativeFixtureAccountQEMU(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.inner == nil {
		return ErrInvalid
	}
	return b.inner.CreateDisabled(ctx, account)
}

func (b *NativeBackendQEMU) SetPasswordDisabled(ctx context.Context, account serviceaccounts.Account, secret []byte) error {
	if b == nil || !nativeFixtureAccountQEMU(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.inner == nil {
		return ErrInvalid
	}
	return b.inner.SetPasswordDisabled(ctx, account, secret)
}

func (b *NativeBackendQEMU) Enable(ctx context.Context, account serviceaccounts.Account) error {
	if b == nil || !nativeFixtureAccountQEMU(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.inner == nil {
		return ErrInvalid
	}
	return b.inner.Enable(ctx, account)
}

func (b *NativeBackendQEMU) Disable(ctx context.Context, account serviceaccounts.Account) error {
	if b == nil || !nativeFixtureAccountQEMU(account) {
		return ErrInvalid
	}
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.inner == nil {
		return ErrInvalid
	}
	return b.inner.Disable(ctx, account)
}

func (b *NativeBackendQEMU) Close() error {
	if b == nil {
		return nil
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.inner == nil {
		return nil
	}
	if err := b.runtime.Close(context.Background()); err != nil {
		return err // Never discard config while runtime teardown is uncertain.
	}
	err := b.inner.Close()
	b.inner = nil
	return err
}
