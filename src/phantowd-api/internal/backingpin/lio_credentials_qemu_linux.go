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
	"runtime"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"golang.org/x/sys/unix"
)

const lioCredentialFixtureTarget = "/sys/kernel/config/target/iscsi/iqn.2026-10.invalid.phantowd:lio-fixture"
const lioCredentialFixturePeer = "iqn.2026-10.invalid.phantowd:client"

// Separate disposable credential/protocol prerequisite. No data LUN/backing,
// product owner or policy-derived target operation. Called only from dedicated
// root LIO guest init before the pre-existing storage/protocol tests.
func RunQEMULIOCredentialFixture() error {
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return ErrUnavailable
	}
	model, err := os.ReadFile("/proc/device-tree/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return ErrUnavailable
	}
	cmdline, err := os.ReadFile("/proc/cmdline")
	if err != nil || !bytes.Contains(cmdline, []byte("init=/usr/libexec/phantowd-lio-fixture-init ")) {
		return ErrUnavailable
	}
	for _, mode := range []string{"mutual-chap", "chap"} {
		if err := runLIOCredentialCase(mode); err != nil {
			return err
		}
	}
	fmt.Println("PHANTOWD_LIO_CREDENTIALS_READY root_only_claim=true typed_fixed_attributes=true same_configfs_acl_refused=true exact_readback=true chap=true mutual_exchange=true wrong_secret_refused=true missing_secret_refused=true stale_outbound_cleared=true restored_drift_review=true no_retry=true teardown_before_release=true data_luns=0 scope=disposable-qemu-only")
	return nil
}

func lioFixtureStore(path, value string) error {
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return ErrUnavailable
	}
	f := os.NewFile(uintptr(fd), "fixed-lio-fixture-attribute")
	n, writeErr := f.Write([]byte(value))
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil || n != len(value) {
		return ErrUnavailable
	}
	return nil
}

func lioFixtureClient(ctx context.Context, mode string) error {
	switch mode {
	case "credential-chap", "credential-mutual", "wrong", "none":
	default:
		return ErrInvalid
	}
	cmd := exec.CommandContext(ctx, "/usr/libexec/phantowd-iscsi-fixture-client", mode)
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.Dir = "/run/phantowd-lio"
	cmd.Stdout, cmd.Stderr = io.Discard, io.Discard
	// The fixed pinned client validates exact protocol refusal, never mere timeout.
	if cmd.Run() != nil {
		return ErrUnavailable
	}
	return nil
}

func runLIOCredentialCase(mode string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	directory, err := os.MkdirTemp("/run/phantowd-lio", "credential-vault-")
	if err != nil {
		return ErrUnavailable
	}
	defer os.RemoveAll(directory) // This invocation's generated tmpfs fixture only.
	secrets, err := iscsicredentials.OpenQEMULIOFixture(directory + "/store")
	if err != nil {
		return err
	}
	target := lioCredentialFixtureTarget
	tpg := target + "/tpgt_1"
	acl := tpg + "/acls/" + lioCredentialFixturePeer
	portal := tpg + "/np/127.0.0.1:3260"
	// New fixed objects only, no fallback/reuse after uncertainty.
	for _, path := range []string{target, tpg, acl} {
		if os.Mkdir(path, 0755) != nil {
			return ErrUnavailable
		}
	}
	for _, item := range [][2]string{{tpg + "/attrib/authentication", "1"},
		{tpg + "/attrib/generate_node_acls", "0"}, {tpg + "/param/AuthMethod", "CHAP"}} {
		if lioFixtureStore(item[0], item[1]) != nil {
			return ErrUnavailable
		}
	}
	tpgFile, err := os.Open(tpg)
	if err != nil {
		return ErrUnavailable
	}
	defer tpgFile.Close()
	authFile, err := os.Open(acl + "/auth")
	if err != nil {
		return ErrUnavailable
	}
	defer authFile.Close()
	// Wrong auth descriptor on the SAME real configfs is not topology authority.
	other := tpg + "/acls/iqn.2026-10.invalid.phantowd:foreign"
	if os.Mkdir(other, 0755) != nil {
		return ErrUnavailable
	}
	otherAuth, err := os.Open(other + "/auth")
	if err != nil {
		return ErrUnavailable
	}
	_, wrongErr := newLIOCredentialSink(tpgFile, []lioAuthSelection{{name: lioCredentialFixturePeer, auth: otherAuth}})
	closeErr := otherAuth.Close()
	if wrongErr == nil || closeErr != nil || unix.Rmdir(other) != nil {
		return ErrReview
	}
	sink, err := newLIOCredentialSink(tpgFile, []lioAuthSelection{{name: lioCredentialFixturePeer, auth: authFile}})
	if err != nil {
		return err
	}
	// Whole-roster refusal must not consume the sink's one installation attempt.
	if !errors.Is(sink.PrepareCredentials(ctx, nil), ErrInvalid) || sink.attempted {
		return ErrReview
	}
	policy := fixtureBackingPolicy(1, "unused.img")
	policy.ISCSI.Targets[0].Name = "iqn.2026-10.invalid.phantowd:lio-fixture"
	peer := &policy.ISCSI.Targets[0].Initiators[0]
	peer.Name = lioCredentialFixturePeer
	peer.Authentication.Mode, peer.Authentication.InitiatorUser = mode, "fixture"
	if mode == "mutual-chap" {
		peer.Authentication.TargetUser, peer.Authentication.TargetSecretRef = "fixture-target", "fixture-outbound"
	} else {
		// Deliberately stale outbound config, cleared by the typed CHAP install.
		if lioFixtureStore(acl+"/auth/userid_mutual", "fixture-target") != nil ||
			lioFixtureStore(acl+"/auth/password_mutual", "synthetic-outbound-only-2026") != nil {
			return ErrUnavailable
		}
	}
	claim, err := secrets.Acquire(ctx, 1, policy, "fixture-target", sink)
	if err != nil {
		return err
	}
	if !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) {
		return ErrReview
	}
	if claim.Prepare(ctx) != nil || sink.verifyDisabled(ctx) != nil {
		return ErrReview
	}
	if !errors.Is(sink.PrepareCredentials(ctx, sink.peers), ErrBusy) {
		return ErrReview
	}
	if os.Mkdir(portal, 0755) != nil || lioFixtureStore(tpg+"/enable", "1") != nil {
		return ErrUnavailable
	}
	clientMode := "credential-chap"
	if mode == "mutual-chap" {
		clientMode = "credential-mutual"
	}
	for _, value := range []string{clientMode, "wrong", "none"} {
		if lioFixtureClient(ctx, value) != nil {
			return ErrUnavailable
		}
	}
	if lioFixtureStore(tpg+"/enable", "0") != nil {
		return ErrUnavailable
	}
	info, err := os.ReadFile(acl + "/info")
	if err != nil || len(info) > 4096 || !bytes.HasPrefix(info, []byte("No active iSCSI Session")) {
		return ErrReview
	}
	if sink.verifyDisabled(ctx) != nil {
		return ErrReview
	}
	if lioFixtureStore(acl+"/auth/password", "deliberately-wrong") != nil ||
		!errors.Is(sink.verifyDisabled(ctx), ErrReview) {
		return ErrReview
	}
	if lioFixtureStore(acl+"/auth/password", "synthetic-chap-only-2026") != nil ||
		!errors.Is(sink.verifyDisabled(ctx), ErrReview) || !errors.Is(sink.PrepareCredentials(ctx, sink.peers), ErrReview) {
		return ErrReview
	}
	if !errors.Is(secrets.Close(), iscsicredentials.ErrBusy) {
		return ErrReview
	}
	// Independent fixture teardown, not revival/retry of the sink.
	// Clients joined, TPG disabled, then ACL/session/auth objects removed.
	for _, path := range []string{portal, acl, tpg, target} {
		if unix.Rmdir(path) != nil {
			return ErrReview
		}
	}
	if _, err := os.Stat(target); !os.IsNotExist(err) {
		return ErrReview
	}
	if err := authFile.Close(); err != nil {
		return ErrReview
	}
	if err := tpgFile.Close(); err != nil {
		return ErrReview
	}
	if claim.Release() != nil || secrets.Close() != nil {
		return ErrReview
	}
	if _, err := sink.peers[0].Incoming.WriteTo(io.Discard); !errors.Is(err, iscsicredentials.ErrClosed) {
		return ErrReview
	}
	return nil
}
