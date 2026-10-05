//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"os/exec"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

// Fixed disposable guest only; no product recovery/stop-retry API. The SAME
// libiscsi context performs fresh two-LUN I/O AFTER the real Owner's refusal.
func qemuLIOHeldOwner(ctx context.Context, owner *writableOwner, backend *qemuLIOTargetBackend,
	policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, lease *mountowner.MountedVolumeSetLease) error {
	cmd := exec.CommandContext(ctx, "/usr/libexec/phantowd-iscsi-fixture-client", "owned-hold")
	cmd.Env, cmd.Dir = []string{"PATH=/usr/bin:/bin"}, "/run/phantowd-lio"
	cmd.Stderr = io.Discard
	input, err := cmd.StdinPipe()
	if err != nil {
		return ErrUnavailable
	}
	defer input.Close()
	output, err := cmd.StdoutPipe()
	if err != nil {
		return ErrUnavailable
	}
	if cmd.Start() != nil {
		return ErrUnavailable
	}
	waited := false
	defer func() {
		if !waited {
			_ = cmd.Process.Kill()
			_ = cmd.Wait() // Join the sole fixed child on every failed handshake.
		}
	}()
	reader := bufio.NewReaderSize(output, 128)
	expect := func(expected string) error {
		line, err := reader.ReadSlice('\n')
		if err != nil || string(line) != expected+"\n" {
			return ErrReview
		}
		return nil
	}
	if expect("PHANTOWD_LIO_HELD_READY") != nil || !qemuLIOSessionState(backend.lioBackend, false) || owner.observe(ctx) != nil {
		return ErrReview
	}
	if !errors.Is(owner.stop(ctx), ErrReview) || !qemuLIOHeldRetained(ctx, owner, backend, policy, secrets, lease) {
		return ErrReview
	}
	if _, err := io.WriteString(input, "C\n"); err != nil || expect("PHANTOWD_LIO_HELD_IO_READY") != nil {
		return ErrReview
	}
	// Read both retained descriptors independently of the client and any path.
	for i, member := range owner.group {
		data := make([]byte, member.blockSize)
		n, err := member.file.ReadAt(data, int64(member.blockSize))
		expected := byte('Z')
		if i == 1 {
			expected = 'W'
		}
		if err != nil || n != len(data) || !bytes.Equal(data, bytes.Repeat([]byte{expected}, len(data))) {
			return ErrReview
		}
	}
	if !qemuLIOHeldRetained(ctx, owner, backend, policy, secrets, lease) {
		return ErrReview
	}
	if _, err := io.WriteString(input, "L\n"); err != nil || expect("PHANTOWD_LIO_CLIENT_READY case=owned-hold") != nil {
		return ErrReview
	}
	err = cmd.Wait()
	waited = true
	if err != nil || !qemuLIOSessionState(backend.lioBackend, true) || !qemuLIOHeldRetained(ctx, owner, backend, policy, secrets, lease) {
		return ErrReview
	}
	// Logout does not clear review or authorize a retry. A SEPARATE test controller
	// now disposes its witnessed fixture, without calling/resetting backend.stop.
	if qemuLIODisposeIdleFixture(ctx, backend.lioBackend) != nil || backend.stops != 1 || !backend.stopAttempted || backend.stopped {
		return ErrReview
	}
	for _, operation := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
		if !errors.Is(operation(), ErrReview) {
			return ErrReview
		}
	}
	owner.mu.Lock()
	err = owner.releaseLocked() // Independent fixture disposal only, never product recovery.
	owner.mu.Unlock()
	if err != nil || owner.phase != writableReview || backend.stops != 1 {
		return ErrReview
	}
	return nil
}

func qemuLIOSessionState(backend *lioBackend, idle bool) bool {
	if backend == nil || len(backend.auth) == 0 {
		return false
	}
	for _, acl := range backend.auth {
		f, err := lioBackendLeaf(acl, "info", unix.O_RDONLY)
		if err != nil {
			return false
		}
		data, readErr := io.ReadAll(io.LimitReader(f, 4097))
		closeErr := f.Close()
		noSession := bytes.HasPrefix(data, []byte("No active iSCSI Session"))
		valid := readErr == nil && closeErr == nil && len(data) > 0 && len(data) <= 4096 && noSession == idle
		clear(data)
		if !valid {
			return false
		}
	}
	return true
}

func qemuLIOHeldRetained(ctx context.Context, owner *writableOwner, backend *qemuLIOTargetBackend,
	policy *naspolicystore.Owner, secrets *iscsicredentials.Owner, lease *mountowner.MountedVolumeSetLease) bool {
	if backend.stops != 1 || !backend.liveAtStop || !backend.stopAttempted || backend.stopped || owner.phase != writableReview ||
		owner.released || owner.credentials == nil || owner.policy == nil || backend.checkEntries() != nil ||
		backend.checkExpected(ctx) != nil || backend.sink.verifyEnabled(ctx) != nil {
		return false
	}
	if !errors.Is(policy.Close(), naspolicystore.ErrBusy) || !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
		return false
	}
	for _, member := range owner.group {
		if member.file == nil || member.pin.consumer != owner || !errors.Is(member.pin.Close(), ErrBusy) {
			return false
		}
		if _, err := member.file.Stat(); err != nil {
			return false
		}
	}
	for _, operation := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
		if !errors.Is(operation(), ErrReview) {
			return false
		}
	}
	return backend.stops == 1
}

// Independent test-only controller AFTER verified logout. It never resets
// lifecycle state, calls backend.stop, force-disables, adopts a foreign object,
// or supplies a product recovery route. Borrowers remain retained until removal.
func qemuLIODisposeIdleFixture(ctx context.Context, backend *lioBackend) error {
	if ctx.Err() != nil || !backend.stopAttempted || backend.stopped || !qemuLIOSessionState(backend, true) ||
		backend.checkEntries() != nil || backend.sink.verifyEnabled(ctx) != nil ||
		lioBackendSet(backend.tpg, "disable_if_idle", "1", false) != nil || lioBackendCheck(backend.tpg, "enable", "0") != nil {
		return ErrReview
	}
	if backend.checkEntries() != nil || !qemuLIOSessionState(backend, true) {
		return ErrReview
	}
	return qemuLIORemoveRemainingFixture(ctx, backend)
}

// Only the independently verified idle test controller may call this. It owns
// no product retry authority and never resets backend/Owner lifecycle flags.
func qemuLIORemoveRemainingFixture(ctx context.Context, backend *lioBackend) error {
	if ctx.Err() != nil || backend.checkEntries() != nil {
		return ErrReview
	}
	for i := len(backend.entries) - 1; i >= 0; i-- {
		entry := backend.entries[i]
		if entry.removed {
			continue // Already removed objects are never retried/adopted.
		}
		if ctx.Err() != nil || entry.file == nil || strings.ContainsAny(entry.name, "/\\\x00") {
			return ErrReview
		}
		if entry.name != "" {
			flags := unix.AT_REMOVEDIR
			if entry.link {
				flags = 0
			}
			if unix.Unlinkat(int(entry.parent.Fd()), entry.name, flags) != nil {
				return ErrReview
			}
		}
		entry.removed = true
		if !entry.link && entry.file.Close() != nil {
			return ErrReview
		}
	}
	if errors.Join(backend.fabric.Close(), backend.core.Close()) != nil {
		return ErrReview
	}
	return nil
}
