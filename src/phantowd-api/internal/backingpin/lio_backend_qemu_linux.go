//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

type qemuLIOTargetBackend struct {
	*lioBackend
	uncertain  bool
	stops      int
	liveAtStop bool
	tracked    []targetBacking
	peers      []iscsicredentials.Credential // opaque borrowed claims, even before sink installation
}

func (b *qemuLIOTargetBackend) PrepareCredentials(ctx context.Context, peers []iscsicredentials.Credential) error {
	b.peers = append([]iscsicredentials.Credential(nil), peers...)
	return b.lioBackend.PrepareCredentials(ctx, peers)
}

func (b *qemuLIOTargetBackend) stop(ctx context.Context) error {
	b.stops++
	b.liveAtStop = true
	for _, member := range b.tracked {
		if _, err := member.file.Stat(); err != nil {
			b.liveAtStop = false
		}
	}
	if len(b.peers) != len(b.target.Initiators) || len(b.tracked) != len(b.target.LUNs) {
		return ErrReview
	}
	for _, peer := range b.peers {
		if _, err := peer.Incoming.WriteTo(io.Discard); err != nil {
			b.liveAtStop = false
		}
	}
	if b.uncertain {
		return ErrReview
	}
	return b.lioBackend.stop(ctx)
}

// No production admission: fixed root-only ARM926 init, no NIC, temporary ext2.
func RunQEMULIOTargetFixture() error {
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrUnavailable
	}
	model, err := os.ReadFile("/proc/device-tree/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return ErrUnavailable
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !bytes.Contains(cmdline, []byte("init=/usr/libexec/phantowd-lio-fixture-init ")) ||
		!bytes.Contains(cmdline, []byte("phantowd.lio_idle=guarded")) {
		return ErrUnavailable
	}
	if err := qemuLIOWriteOnlyProbe(); err != nil {
		return err
	}
	err = mountowner.WithQEMUMountedSet("/srv/phantowd/volumes/qemu-only", func(set *mountowner.MountedVolumeSet) error {
		workspace, err := os.MkdirTemp("/srv/phantowd/volumes/qemu-plan", "lio-target-")
		if err != nil {
			return ErrUnavailable
		}
		defer os.RemoveAll(workspace) // Generated fixture contents only, after Owner disposal.
		for _, kind := range []string{"normal", "access", "active-session", "existing-target", "existing-second-storage", "partial-delete", "foreign-acl", "foreign-lun", "foreign-grant", "foreign-portal", "extra-tpg", "replace-second", "permission-drift", "uncertain"} {
			if err := runQEMULIOTargetCase(set, workspace, kind); err != nil {
				// Fixed case label only; never print configfs/library/credential errors.
				fmt.Printf("PHANTOWD_LIO_ERROR phase=owned-target-%s\n", kind)
				return ErrReview
			}
		}
		return nil
	})
	if err != nil {
		return err
	}
	fmt.Println("PHANTOWD_LIO_TARGET_ACCESS_READY peers=2 separate_credentials=true primary_readwrite=true peer_readonly=true ungranted_refused=true cross_credentials_refused=true foreign_refused=true original_data_preserved=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_LIO_TARGET_FAULTS_READY existing_target_preserved=true later_storage_preserved=true partial_setup_cleaned=true partial_teardown_retained=true no_retry=true independent_disposal=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_LIO_TOPOLOGY_READY bounded_census=true foreign_acl_refused=true foreign_lun_refused=true foreign_grant_refused=true foreign_preserved=true sources_retained=true no_retry=true writer_exclusion=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_LIO_ENDPOINTS_READY foreign_portal_refused=true extra_tpg_refused=true foreign_preserved=true sources_retained=true no_retry=true independent_disposal=true writer_exclusion=false scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_LIO_TARGET_SESSION_READY active_stop_refused=true same_client_readwrite=true complete_resources_retained=true owner_review=true no_retry=true logout_not_recovery=true independent_fixture_disposal=true scope=disposable-qemu-only")
	fmt.Println("PHANTOWD_LIO_TARGET_READY complete_roster=true luns=0,7 block_sizes=512,4096 actual_mount_owner=true proc_fd_binding=true chap=true exact_data=true write_only_open_modes=true active_attribute_checks=true later_member_drift=true uncertain_retains_all=true no_retry=true idle_teardown_before_release=true scope=disposable-qemu-only")
	return nil
}

func qemuLIOWriteOnlyProbe() error {
	const storage = "/sys/kernel/config/target/core/fileio_0/phantowd-write-only-probe"
	const target = "/sys/kernel/config/target/iscsi/iqn.2026-10.invalid.phantowd:write-only-probe"
	const tpg = target + "/tpgt_1"
	for _, path := range []string{storage, target, tpg} {
		if os.Mkdir(path, 0755) != nil {
			return ErrUnavailable
		}
	}
	for _, item := range [][2]string{{storage, "control"}, {tpg, "disable_if_idle"}} {
		dir, err := os.Open(item[0])
		if err != nil {
			return ErrUnavailable
		}
		wrong, wrongErr := lioBackendLeaf(dir, item[1], unix.O_RDWR)
		if wrong != nil {
			_ = wrong.Close()
		}
		if wrongErr == nil {
			_ = dir.Close()
			return ErrReview
		}
		right, rightErr := lioBackendLeaf(dir, item[1], unix.O_WRONLY)
		if rightErr != nil {
			_ = dir.Close()
			return ErrReview
		}
		if errors.Join(right.Close(), dir.Close()) != nil {
			return ErrReview
		}
	}
	for _, path := range []string{tpg, target, storage} {
		if os.Remove(path) != nil {
			return ErrReview
		}
	}
	return nil
}

func runQEMULIOTargetCase(set *mountowner.MountedVolumeSet, workspace, kind string) (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	dir := workspace + "/" + kind
	if os.Mkdir(dir, 0700) != nil {
		return ErrUnavailable
	}
	lease, _, err := set.Acquire(ctx)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, lease.Close()) }()
	paths := []string{dir + "/first", dir + "/second"}
	relative := []string{filepath.Base(workspace) + "/" + kind + "/first", filepath.Base(workspace) + "/" + kind + "/second"}
	for i, path := range paths {
		if err := os.WriteFile(path, make([]byte, 4096*(i+1)), 0600); err != nil {
			return err
		}
	}
	if os.Mkdir(dir+"/policy", 0700) != nil {
		return ErrUnavailable
	}
	store, err := naspolicystore.Open(dir + "/policy")
	if err != nil {
		return err
	}
	p := fixtureTargetPolicy(1, relative[0], relative[1])
	p.ISCSI.Targets[0].Name = "iqn.2026-10.invalid.phantowd:lio-fixture"
	p.ISCSI.Targets[0].Initiators[0].Name = lioCredentialFixturePeer
	p.ISCSI.Targets[0].Initiators[0].Authentication.InitiatorUser = "fixture"
	if kind == "access" {
		p.ISCSI.Targets[0].Initiators = append(p.ISCSI.Targets[0].Initiators, iscsipolicy.Initiator{
			Name:           "iqn.2026-10.invalid.phantowd:peer",
			Authentication: iscsipolicy.Authentication{Mode: "chap", InitiatorUser: "fixture-peer", InitiatorSecretRef: "fixture-peer"},
			Grants:         []iscsipolicy.Grant{{LUNID: "fixture-lun", Access: "ro"}},
		})
	}
	commitErr := store.Commit(0, p)
	if err := errors.Join(commitErr, store.Close()); err != nil {
		return err
	}
	policy, err := naspolicystore.OpenOwner(dir + "/policy")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, policy.Close()) }()
	secrets, err := iscsicredentials.OpenQEMULIOFixture(dir + "/secrets")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, secrets.Close()) }()
	fabric, err := os.Open("/sys/kernel/config/target/iscsi")
	if err != nil {
		return err
	}
	core, err := os.Open("/sys/kernel/config/target/core/fileio_0")
	if err != nil {
		_ = fabric.Close()
		return err
	}
	lio, createErr := newLIOBackend(p, "fixture-target", fabric, core)
	closeErr := errors.Join(fabric.Close(), core.Close()) // Constructor must retain independent roots.
	if createErr != nil || closeErr != nil {
		return ErrUnavailable
	}
	backend := &qemuLIOTargetBackend{lioBackend: lio, uncertain: kind == "uncertain"}
	var inputs []targetSelection
	for i, path := range paths {
		pin, _, err := OpenFromMountedLease(lease, "qemu-plan", relative[i], uint64(4096*(i+1)))
		if err != nil {
			return err
		}
		defer func() { result = errors.Join(result, pin.Close()) }()
		fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC|unix.O_NONBLOCK, 0)
		if err != nil {
			return err
		}
		file := os.NewFile(uintptr(fd), "synthetic-lio-member")
		defer func() {
			if _, err := file.Stat(); err == nil {
				result = errors.Join(result, file.Close())
			}
		}()
		id := iscsipolicy.BackingID("fixture-backing")
		if i == 1 {
			id = "fixture-second"
		}
		inputs = append(inputs, targetSelection{backingID: id, pin: pin, file: file})
	}
	inputs[0], inputs[1] = inputs[1], inputs[0]
	owner, err := newTargetWritableOwner(ctx, inputs, backend, policy, 1, secrets, 1, "fixture-target")
	if err != nil {
		return err
	}
	backend.tracked = append([]targetBacking(nil), owner.group...)
	if kind == "existing-target" || kind == "existing-second-storage" {
		return qemuLIOSetupCollision(ctx, owner, backend, kind, paths)
	}
	if err := owner.start(ctx); err != nil {
		return err
	}
	if err := owner.observe(ctx); err != nil {
		return err
	}
	if !errors.Is(policy.Close(), naspolicystore.ErrBusy) || !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) || !errors.Is(lease.Close(), mountowner.ErrBusy) {
		return ErrReview
	}
	cmd := exec.CommandContext(ctx, "/usr/libexec/phantowd-iscsi-fixture-client", "owned-target")
	cmd.Env, cmd.Dir = []string{"PATH=/usr/bin:/bin"}, "/run/phantowd-lio"
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	if cmd.Run() != nil {
		return ErrUnavailable
	}
	if kind == "access" {
		for _, mode := range []string{"owned-peer-ro", "owned-peer-cross", "foreign"} {
			peer := exec.CommandContext(ctx, "/usr/libexec/phantowd-iscsi-fixture-client", mode)
			peer.Env, peer.Dir = cmd.Env, cmd.Dir
			peer.Stdout, peer.Stderr = io.Discard, io.Discard
			if peer.Run() != nil {
				return ErrUnavailable
			}
		}
	}
	// Independently prove actual writes reached both original retained files.
	for i, path := range paths {
		data, err := os.ReadFile(path)
		block := 512
		if i == 1 {
			block = 4096
		}
		if err != nil || len(data) != 4096*(i+1) || !bytes.Equal(data[block:block*2], bytes.Repeat([]byte{byte('X' + i)}, block)) {
			return ErrReview
		}
	}
	if err := owner.observe(ctx); err != nil {
		return err
	}
	switch kind {
	case "foreign-acl", "foreign-lun", "foreign-grant", "foreign-portal", "extra-tpg":
		if err := qemuLIOForeignTopology(ctx, owner, backend, kind, policy, secrets, lease); err != nil {
			return err
		}
		return nil
	case "partial-delete":
		if err := qemuLIOPartialDelete(ctx, owner, backend, policy, secrets, lease); err != nil {
			return err
		}
	case "active-session":
		if err := qemuLIOHeldOwner(ctx, owner, backend, policy, secrets, lease); err != nil {
			return err
		}
	case "replace-second":
		if os.Rename(paths[1], paths[1]+"-old") != nil || os.WriteFile(paths[1], make([]byte, 8192), 0600) != nil {
			return ErrUnavailable
		}
		if !errors.Is(owner.observe(ctx), ErrReview) {
			return ErrReview
		}
		replacement, err := os.ReadFile(paths[1])
		if err != nil || !bytes.Equal(replacement, make([]byte, 8192)) {
			return ErrReview
		}
	case "permission-drift":
		if lioFixtureStore(lioCredentialFixtureTarget+"/tpgt_1/acls/"+lioCredentialFixturePeer+"/lun_7/write_protect", "1") != nil {
			return ErrUnavailable
		}
		if !errors.Is(owner.observe(ctx), ErrReview) {
			return ErrReview
		}
	default:
		err := owner.stop(ctx)
		if kind == "normal" && err != nil {
			return err
		}
		if kind == "uncertain" && !errors.Is(err, ErrReview) {
			return ErrReview
		}
	}
	if backend.stops != 1 || !backend.liveAtStop {
		return ErrReview
	}
	if kind == "uncertain" {
		if owner.released || owner.credentials == nil || owner.policy == nil {
			return ErrReview
		}
		for _, member := range owner.group {
			if member.file == nil || member.pin.consumer != owner {
				return ErrReview
			}
			if _, err := member.file.Stat(); err != nil {
				return ErrReview
			}
		}
		if live, err := lio.running(ctx); !live || err != nil {
			return ErrReview
		}
		for _, op := range []func() error{func() error { return owner.start(ctx) }, func() error { return owner.observe(ctx) }, func() error { return owner.stop(ctx) }, owner.close} {
			if !errors.Is(op(), ErrReview) {
				return ErrReview
			}
		}
		if backend.stops != 1 {
			return ErrReview
		}
		// Independent test-only disposal AFTER retained-state/no-retry assertions.
		// The uncertain wrapper never attempted this underlying backend teardown.
		if err := lio.stop(ctx); err != nil {
			return err
		}
		owner.mu.Lock()
		err := owner.releaseLocked()
		owner.mu.Unlock()
		if err != nil {
			return err
		}
	} else if !owner.released || kind != "active-session" && kind != "partial-delete" && !lio.stopped {
		return ErrReview
	}
	if _, err := os.Stat(lioCredentialFixtureTarget); !errors.Is(err, os.ErrNotExist) {
		return ErrReview
	}
	for _, member := range owner.group {
		if member.file != nil || !member.pin.closed {
			return ErrReview
		}
	}
	for _, peer := range backend.sink.peers {
		if _, err := peer.Incoming.WriteTo(io.Discard); !errors.Is(err, iscsicredentials.ErrClosed) {
			return ErrReview
		}
	}
	return nil
}
