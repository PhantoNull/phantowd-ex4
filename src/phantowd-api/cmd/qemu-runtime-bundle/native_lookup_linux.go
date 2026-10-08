//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
	"golang.org/x/sys/unix"
)

const nativeLookupRoot = "/run/phantowd-native-lookup"

// A separate, fixed guest-only experiment after every prior Samba Owner closes.
// No product constructor, persistent storage, password, passdb or HTTP input.
// Lifecycle needs its OWN real Unix bootstrap but never claims the independent
// libc/configuration/handoff proofs. Native still runs every original scenario.
func nativeLookupFixture(bootstrapOnly bool) (result error) {
	commandLine, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(" "+string(commandLine)+" ", " phantowd_samba_ext4_fixture=1 ") {
		return errors.New("native lookup fixture guard")
	}
	var fs unix.Statfs_t
	if unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("native lookup requires disposable tmpfs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	authority := "/run/phantowd-native-authority"
	for _, name := range []string{authority, authority + "/registry", authority + "/operations"} {
		if err := os.Mkdir(name, 0700); err != nil {
			return err
		}
	}
	seed, err := serviceaccountstore.Open(authority + "/registry")
	if err != nil {
		return err
	}
	err = seed.Initialize(2000, 2010)
	if err = errors.Join(err, seed.Close()); err != nil {
		return err
	}
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		// This fixed guest has no imported/offline identity domains.
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	owner, err := identityowner.Open(authority, inventory)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, owner.Close()) }()
	for i, name := range []string{"qpmanaged", "qpsecond"} {
		account, err := owner.Reserve(ctx, uint64(i+1), name, name)
		if err != nil || account.UID != uint32(2000+i) || account.GID != account.UID || account.State != serviceaccounts.Disabled {
			return errors.New("native fixture allocation mismatch")
		}
		if err := owner.Operation(account.ID).Step(ctx, 1); err != nil {
			return fmt.Errorf("native private group: %w", err)
		}
		if got, err := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, owner); !errors.Is(err, identityowner.ErrPending) || got.Fingerprint() != [32]byte{} {
			return errors.New("incomplete native fixture accepted")
		}
		if err := owner.Operation(account.ID).Step(ctx, 3); err != nil {
			return fmt.Errorf("native private user: %w", err)
		}
	}
	before, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || len(before.Registry.Accounts) != 2 || len(before.Samba) != 0 {
		return errors.New("native lookup fixture not pre-enrollment")
	}
	lookup, err := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, owner)
	if err != nil || lookup.Fingerprint() != before.Fingerprint {
		return errors.New("native lookup fixture owner mismatch")
	}
	if bootstrapOnly {
		return nil // Real Owner closes; no qualification marker or state transfer.
	}
	passwd, group, nss, err := lookup.LookupDocuments()
	if err != nil {
		return err
	}
	for _, name := range []string{nativeLookupRoot, nativeLookupRoot + "/etc", nativeLookupRoot + "/lib", nativeLookupRoot + "/usr", nativeLookupRoot + "/fixture"} {
		if err := os.Mkdir(name, 0755); err != nil {
			return err
		}
	}
	for name, contents := range map[string]string{"etc/passwd": passwd, "etc/group": group, "etc/nsswitch.conf": nss, "fixture/charset": ""} {
		file, err := os.OpenFile(nativeLookupRoot+"/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0644)
		if err != nil {
			return err
		}
		_, err = file.WriteString(contents)
		if err = errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	// The pure derivation callback has ended before any staging or execution.
	// Re-observe before launch; the snapshot does not claim retained authority.
	fresh, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, fresh) {
		return errors.New("native lookup changed before libc probe")
	}
	empty, err := os.OpenFile(authority+"/empty-input", os.O_CREATE|os.O_EXCL|os.O_RDONLY, 0600)
	if err != nil {
		return err
	}
	if err := empty.Close(); err != nil {
		return err
	}
	if err := captureNativeLookup(ctx, authority, true); err != nil {
		return err
	}
	// Controlled faults affect ONLY the child lookup documents, never the
	// Owner's native Unix database/journals. Each independent single-use capture
	// verifies exit and group absence before restoring its temporary inputs.
	for _, fault := range []struct{ file, contents string }{
		{"passwd", strings.Replace(passwd, ":2000:2000:", ":2002:2002:", 1)},
		{"group", group + "unexpected:!:2010:qpmanaged\n"},
		{"passwd", passwd + "qpwriter:!:1801:1800::/:/sbin/nologin\n"},
	} {
		if err := os.WriteFile(nativeLookupRoot+"/etc/"+fault.file, []byte(fault.contents), 0644); err != nil {
			return err
		}
		if err := captureNativeLookup(ctx, authority, false); err != nil {
			return fmt.Errorf("native libc fault %s: %w", fault.file, err)
		}
		original := passwd
		if fault.file == "group" {
			original = group
		}
		if err := os.WriteFile(nativeLookupRoot+"/etc/"+fault.file, []byte(original), 0644); err != nil {
			return err
		}
	}
	if err := captureNativeLookup(ctx, authority, true); err != nil {
		return errors.Join(errors.New("restored native lookup failed"), err)
	}
	after, err := owner.NativeLookupSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("libc probe changed native Owner state")
	}
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_NSS_READY accounts=2 owner_derived=true libc=true private_groups=true foreign_omitted=true readonly_root=true caps_zero=true no_state=true unchanged_owner=true stopped_reaped=true daemon_installed=false scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_NSS_REFUSAL_READY changed_uid=true supplementary_group=true foreign_user=true restored_lookup=true unchanged_owner=true stopped_reaped=true scope=qemu-only")
	if err := runtimebundle.ProbeNativeLookupConfigurationQEMU(ctx, lookup); err != nil {
		return err
	}
	after, err = owner.NativeLookupSnapshot(ctx)
	if err != nil || !reflect.DeepEqual(before, after) {
		return errors.New("native configuration probe changed native Owner state")
	}
	return nil
}

func captureNativeLookup(ctx context.Context, authority string, accepted bool) (result error) {
	const helperPath = "/usr/sbin/phantowd-samba-root-launcher"
	helper, err := os.Open(helperPath)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, helper.Close()) }()
	empty, err := os.Open(authority + "/empty-input")
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, empty.Close()) }()
	capture, err := processowner.NewCapture(processowner.CaptureSpec{
		ExecutableLabel: helperPath, Args: []string{"native-lookup"},
		RunAs:   &processowner.Credentials{UID: 0, GID: 0},
		Timeout: 10 * time.Second, StopTimeout: time.Second,
	}, helper, empty)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, capture.Close(context.Background())) }()
	observed, err := capture.Capture(ctx)
	defer clear(observed.Stdout)
	defer clear(observed.Stderr)
	wanted, stderr, exit := "", "PHANTOWD_NATIVE_LIBC_LOOKUP_REFUSED\n", 1
	if accepted {
		wanted = "PHANTOWD_NATIVE_LIBC_LOOKUP_READY accounts=2 private_groups=true foreign_omitted=true readonly_root=true caps_zero=true no_state=true scope=qemu-only\n"
		stderr, exit = "", 0
	}
	if err != nil || observed.Kind != processowner.CaptureExited || observed.ExitCode != exit ||
		string(observed.Stdout) != wanted || string(observed.Stderr) != stderr {
		return fmt.Errorf("native libc probe failed: kind=%v exit=%d error=%v stderr=%q", observed.Kind, observed.ExitCode, err, observed.Stderr)
	}
	if settled, err := capture.Settled(ctx); err != nil || !settled {
		return errors.New("native lookup process group remains")
	}
	return nil
}
