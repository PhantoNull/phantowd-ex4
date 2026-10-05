//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

// Fill the SAME authority with actual distinct objects, not injected map keys.
// A two-member target cannot publish a prefix when only one slot remains.
// Prepared owners only: no child/configfs/session/network effects are needed.
func targetUseCapacityCase(ctx context.Context, lease *mountowner.MountedVolumeSetLease, dir string, paths, relative []string,
	inputs []targetSelection, policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, uses *backingUseOwner) (result error) {
	if iscsipolicy.MaxBackings != 64 {
		return ErrInvalid // The mandatory evidence contract fixes this tested bound.
	}
	var held []*writableOwner
	defer func() {
		for i := len(held) - 1; i >= 0; i-- {
			result = errors.Join(result, held[i].close())
		}
	}()
	for i := 0; i < iscsipolicy.MaxBackings-1; i++ {
		name := fmt.Sprintf("held-%02d", i)
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, make([]byte, 4096), 0600); err != nil {
			return err
		}
		pin, _, err := OpenFromMountedLease(lease, "qemu-plan", filepath.Join(filepath.Dir(relative[0]), name), 4096)
		if err != nil {
			return err
		}
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return errors.Join(err, pin.Close())
		}
		file := os.NewFile(uintptr(fd), "capacity-fixture-member")
		owner, err := newWritableOwner(pin, file, &fixtureWritableBackend{}, uses)
		if err != nil {
			return errors.Join(err, file.Close(), pin.Close())
		}
		held = append(held, owner)
	}
	backend := &fixtureTargetBackend{}
	target, err := newTargetWritableOwner(ctx, inputs, backend, policy, 1, secrets, 1, "fixture-target", uses)
	if target != nil || !errors.Is(err, ErrBusy) {
		if target != nil {
			_ = target.close()
		}
		return errors.New("whole target exceeded actual-object capacity")
	}
	if backend.prepareCalls != 0 || backend.stopCalls != 0 || backend.cmd != nil {
		return errors.New("capacity refusal had backend effects")
	}
	for _, input := range inputs {
		if input.pin.consumer != nil {
			return errors.New("capacity refusal consumed a caller pin")
		}
		if _, err := input.file.Stat(); err != nil {
			return err
		}
	}
	// Admit the first unused member through the SAME authority. It must still
	// have the one free slot; the failed complete-target admission claimed none.
	first, err := newWritableOwner(inputs[0].pin, inputs[0].file, &fixtureWritableBackend{}, uses)
	if err != nil {
		return errors.New("overflow refusal published a prefix reservation")
	}
	held = append(held, first)
	second, err := newWritableOwner(inputs[1].pin, inputs[1].file, &fixtureWritableBackend{}, uses)
	if second != nil || !errors.Is(err, ErrBusy) || inputs[1].pin.consumer != nil {
		if second != nil {
			_ = second.close()
		}
		return errors.New("actual full authority admitted an extra object")
	}
	if _, err := inputs[1].file.Stat(); err != nil {
		return err
	}
	if !errors.Is(uses.close(), ErrBusy) {
		return errors.New("full authority closed with prepared consumers")
	}
	// Verified closure of two consumers frees exactly two slots. Reopen only
	// the first consumed fixture input; the second original caller stays live.
	if err := errors.Join(first.close(), held[0].close()); err != nil {
		return err
	}
	pin, _, err := OpenFromMountedLease(lease, "qemu-plan", relative[0], 4096)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, pin.Close()) }()
	fd, err := unix.Open(paths[0], unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), "capacity-reused-member")
	defer func() {
		if _, err := file.Stat(); err == nil {
			result = errors.Join(result, file.Close())
		}
	}()
	inputs[0] = targetSelection{backingID: inputs[0].backingID, pin: pin, file: file}
	target, err = newTargetWritableOwner(ctx, inputs, &fixtureTargetBackend{}, policy, 1, secrets, 1, "fixture-target", uses)
	if err != nil {
		return fmt.Errorf("freed capacity did not admit complete roster: %w", err)
	}
	held = append(held, target)
	if err := target.close(); err != nil {
		return err
	}
	// This also proves the refused admissions left no hidden source claims.
	return errors.Join(policy.Close(), secrets.Close())
}
