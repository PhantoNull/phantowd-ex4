//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

func nativeCredentialFixture(lifecycle bool) (result error) {
	commandLine, err := os.ReadFile("/proc/cmdline")
	var fs unix.Statfs_t
	if err != nil || !strings.Contains(" "+string(commandLine)+" ", " phantowd_samba_ext4_fixture=1 ") ||
		unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("native credential fixture guard")
	}
	// Initialize Go's pipe poller before establishing the descriptor baseline.
	warmRead, warmWrite, err := os.Pipe()
	if err != nil {
		return err
	}
	if err := errors.Join(warmRead.Close(), warmWrite.Close()); err != nil {
		return err
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	started := time.Now()
	defer cancel()
	authority := "/run/phantowd-native-authority"
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	bootstrap, err := identityowner.Open(authority, inventory)
	if err != nil {
		return err
	}
	lookup, err := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, bootstrap)
	registry, native, snapshotErr := bootstrap.Snapshot(ctx)
	closeErr := bootstrap.Close()
	if err != nil || snapshotErr != nil || closeErr != nil || len(registry.Accounts) != 2 || len(native) != 2 {
		return errors.New("native credential bootstrap lookup")
	}
	// Bootstrap closes without an active consumer. The backend-bound Open below
	// is NEW admission, never a claim of continuous identity authority.
	documents, err := runtimebundle.SambaCredentialDocumentsQEMU(lookup)
	if err != nil {
		return err
	}
	const root = "/run/phantowd-native-samba-root"
	const state = "/run/phantowd-native-samba-state"
	// Samba's fixed IPC$ service checks its default /tmp directory even when
	// this experiment exposes no data shares. It remains empty and read-only
	// under the child root; no mutable scratch or host directory is granted.
	for _, name := range []string{root, root + "/etc", root + "/etc/samba", root + "/lib", root + "/usr", root + "/state", root + "/tmp"} {
		if err := os.Mkdir(name, 0755); err != nil {
			return err
		}
	}
	for _, name := range []string{state, state + "/private", state + "/lock", state + "/state", state + "/cache", state + "/pid", state + "/rpc"} {
		if err := os.Mkdir(name, 0700); err != nil {
			return err
		}
	}
	for name, contents := range documents {
		mode := os.FileMode(0644)
		if name == "samba/smb.conf" {
			mode = 0600
		}
		file, err := os.OpenFile(root+"/etc/"+name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
		if err != nil {
			return err
		}
		_, err = file.WriteString(contents)
		if err := errors.Join(err, file.Close()); err != nil {
			return err
		}
	}
	for _, entry := range []struct {
		path  string
		flags uintptr
	}{
		{"/run/phantowd-samba-code", unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV},
		{root + "/etc", unix.MS_RDONLY | unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
		{state, unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC},
	} {
		if err := unix.Mount(entry.path, entry.path, "", unix.MS_BIND, ""); err != nil {
			return err
		}
		if err := unix.Mount("", entry.path, "", unix.MS_BIND|unix.MS_REMOUNT|entry.flags, ""); err != nil {
			return err
		}
	}
	files, aliases, err := inputs()
	if err != nil {
		return err
	}
	plan, err := runtimebundle.NewPlan(files, aliases)
	if err != nil {
		return err
	}
	var callers []*os.File
	for _, path := range []string{"/run/phantowd-samba-code", root + "/etc", state} {
		fd, err := unix.Open(path, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			for _, caller := range callers {
				_ = caller.Close()
			}
			return err
		}
		callers = append(callers, os.NewFile(uintptr(fd), "native-credential-authority-caller"))
	}
	runtime, err := plan.NewNativeSambaRuntimeQEMU(ctx, callers[0], callers[1], callers[2], lookup)
	for _, caller := range callers {
		err = errors.Join(err, caller.Close())
	}
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, runtime.Close(context.Background())) }()
	backend, err := smbexec.NewNativeBackendQEMU(ctx, runtime)
	if err != nil {
		return fmt.Errorf("native backend admission: %w", err)
	}
	owner, err := identityowner.OpenWithSMBBackend(authority, inventory, backend)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, owner.Close()) }()
	var revocationLeases []*identityowner.FileServiceLease
	defer func() {
		if len(revocationLeases) == 0 {
			return
		}
		// Cleanup never drops a live/uncertain service reference. Stop/reap all
		// clients and the daemon first, outside both Owner and runtime gates.
		if err := runtime.StopNativeDaemonQEMU(context.Background()); err != nil {
			result = errors.Join(result, err)
			return
		}
		for _, lease := range revocationLeases {
			result = errors.Join(result, lease.Release())
		}
	}()
	for _, confirmed := range native {
		op := owner.SMB(confirmed.Account.ID)
		if err := op.Begin(ctx, confirmed.Revision); err != nil {
			return fmt.Errorf("native enrollment begin elapsed=%v context=%v: %w", time.Since(started), ctx.Err(), err)
		}
		journal, err := op.Load(ctx)
		if err != nil || journal.Phase != smbprovision.Reserved {
			return errors.New("native enrollment intent")
		}
		if err := op.Step(ctx, journal.Revision); err != nil {
			return fmt.Errorf("native disabled creation elapsed=%v context=%v: %w", time.Since(started), ctx.Err(), err)
		}
		journal, err = op.Load(ctx)
		if err != nil || journal.Phase != smbprovision.DisabledNoPassword || journal.SID == "" {
			return errors.New("native disabled confirmation")
		}
		sid := journal.SID
		// Synthetic fixture password, not an operator credential. Backend sends
		// only two stdin lines; neither argv, journals nor markers contain it.
		secret := []byte("native-qemu-only-password-29")
		err = op.SetPasswordDisabled(ctx, journal.Revision, secret)
		clear(secret)
		if err != nil {
			return fmt.Errorf("native disabled password elapsed=%v context=%v: %w", time.Since(started), ctx.Err(), err)
		}
		journal, err = op.Load(ctx)
		if err != nil || journal.Phase != smbprovision.CredentialSetDisabled || journal.SID != sid {
			return errors.New("native password enabled or SID changed")
		}
		if err := op.Enable(ctx, journal.Revision); err != nil {
			return fmt.Errorf("native explicit enable elapsed=%v context=%v: %w", time.Since(started), ctx.Err(), err)
		}
		journal, err = op.Load(ctx)
		if err != nil || journal.Phase != smbprovision.Enabled || journal.SID != sid {
			return errors.New("native explicit enable confirmation")
		}
	}
	// Independent fresh guest: real enrollment is required here, but the native
	// campaign owns the idle/live-disable and backend-binding proofs. Do not
	// start/disable/stop a redundant first daemon before the startup coordinator.
	// The complete suite still requires every original proof from all3 guests.
	if lifecycle {
		if err := nativePlannedCandidateFixtureQEMU(owner, backend); err != nil {
			return fmt.Errorf("native planned candidate: %w", err)
		}
		if err := owner.Close(); err != nil {
			return err
		}
		if err := runtime.Close(context.Background()); err != nil {
			return err
		}
		if err := nativeIdentityStartupFixtureQEMU(plan, lookup, authority, inventory, native[0].Account.ID); err != nil {
			return fmt.Errorf("native retained startup: %w", err)
		}
		if err := nativeIdentityFaultSubprocessQEMU(); err != nil {
			return err
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(after) != len(before) {
			return errors.New("native lifecycle descriptor leak")
		}
		nativeCredentialEnrollmentMarkerQEMU()
		fmt.Println(plannedCandidateMarkerQEMU)
		fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_STARTUP_READY startup_bound=true exact_backend=true before_start_busy=true after_start_busy=true duplicate_refused=true canceled_start_refused=true complete_observation=true serialized_scans=true accepted_cancellation=true stopped_reaped=true close_before_release=true no_fd_leak=true coordinator_disable=true qualified_pair=true same_peer_session=true target_denied=true stale_revision_refused=true canceled_disable_refused=true serialized_disable=true prepared_disable_refused=true stopped_disable_refused=true service_owner=false scope=qemu-only")
		fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_IDENTITY_FAULT_READY state_drift=true before_worker=true pending_retained=true groups_stopped=true capture_settled=true authority_busy=true inputs_retained=true restoration_refused=true close_no_retry=true subprocess_disposal=true no_fd_leak=true service_owner=false scope=qemu-only")
		return nil
	}
	// Final passdb assertions belong to the complete Owner-locked observation
	// below. Do not repeat the same full scan outside that lock at the end of
	// the cumulative enrollment budget. All per-worker admission fences and
	// deadlines remain unchanged.
	if err := nativeIdentityBackendProbeQEMU(owner, backend); err != nil {
		return fmt.Errorf("native read-only backend binding: %w", err)
	}
	// Authentication is a new, separately bounded phase; the original 60-second
	// credential campaign remains unchanged. The outer guest still has 180s.
	daemonContext, stopDaemonContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer stopDaemonContext()
	canceled, cancelStart := context.WithCancel(daemonContext)
	cancelStart()
	if err := runtime.StartNativeDaemonQEMU(canceled); !errors.Is(err, context.Canceled) {
		return errors.New("native canceled start admitted")
	}
	if err := runtime.StartNativeDaemonQEMU(daemonContext); err != nil {
		return fmt.Errorf("native same-state daemon: %w", err)
	}
	if err := runtime.StartNativeDaemonQEMU(daemonContext); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("native duplicate start admitted")
	}
	// Authentication has completed. Idle-disable verification is a different
	// phase: do not reuse the remaining startup deadline for three workers,
	// journal confirmation and the two fresh-login probes.
	idleContext, stopIdleContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer stopIdleContext()
	idleStarted := time.Now()
	// No client is held open here. The unchanged backend must perform its two
	// complete stable-absence observations against the SAME running daemon.
	disable := owner.SMB(native[0].Account.ID)
	journal, err := disable.Load(idleContext)
	if err != nil || journal.Phase != smbprovision.Enabled {
		return errors.New("native idle disable admission")
	}
	sid := journal.SID
	if err := disable.Disable(idleContext, journal.Revision); err != nil {
		return fmt.Errorf("native idle disable elapsed=%v context=%v: %w", time.Since(idleStarted), idleContext.Err(), err)
	}
	journal, err = disable.Load(idleContext)
	if err != nil || journal.Phase != smbprovision.Disabled || journal.SID != sid {
		return errors.New("native idle disable journal confirmation")
	}
	if err := runtime.VerifyNativeIdleDisableQEMU(idleContext); err != nil {
		return fmt.Errorf("native idle disable authentication elapsed=%v context=%v: %w", time.Since(idleStarted), idleContext.Err(), err)
	}
	// Separate bounded active-session phase. The tagged native adapter has a
	// fixed ten-second revocation budget for complete worker admissions; generic
	// revocation stays five seconds. Native status reads include full admission
	// with a four-second limit; generic status reads stay two seconds.
	// Re-enable and NEW identity-consumer preparation precede held clients.
	// Give this bounded preparation its own twenty seconds instead of charging
	// it to the unchanged forty-five-second live-session campaign. All live
	// pair/revocation/continuity/login checks remain inside that fixed budget.
	preparationContext, stopPreparationContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer stopPreparationContext()
	if err := disable.Enable(preparationContext, journal.Revision); err != nil {
		return fmt.Errorf("native session explicit re-enable: %w", err)
	}
	journal, err = disable.Load(preparationContext)
	if err != nil || journal.Phase != smbprovision.Enabled || journal.SID != sid {
		return errors.New("native session enable confirmation")
	}
	// This consumer is acquired for an already-running disposable fixture;
	// startup authority and complete product supervision remain separate gates.
	evidence, err := owner.FileServiceSnapshot(preparationContext)
	if err != nil {
		return fmt.Errorf("native live identity evidence: %w", err)
	}
	consumer, err := owner.RetainSMBFileServiceSnapshot(preparationContext, evidence.Fingerprint, backend)
	if err != nil {
		return fmt.Errorf("native live identity retention: %w", err)
	}
	revocationLeases = append(revocationLeases, consumer)
	if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("native pre-revocation identity authority released")
	}
	stopPreparationContext()
	sessionContext, stopSessionContext := context.WithTimeout(context.Background(), 45*time.Second)
	defer stopSessionContext()
	sessionStarted := time.Now()
	if err := runtime.StartNativeClientsQEMU(sessionContext); err != nil {
		return fmt.Errorf("native held session clients: %w", err)
	}
	pair, err := backend.ObserveNativeSessionPairQEMU(sessionContext)
	if err != nil {
		return fmt.Errorf("native real qualified session pair: %w", err)
	}
	successor, err := disable.DisableForFileService(sessionContext, journal.Revision, consumer)
	if err != nil {
		return fmt.Errorf("native live session revoke elapsed=%v context=%v: %w", time.Since(sessionStarted), sessionContext.Err(), err)
	}
	revocationLeases = append(revocationLeases, successor)
	if err := consumer.Verify(sessionContext); !errors.Is(err, identityowner.ErrReview) {
		return errors.New("native superseded identity token verified")
	}
	if err := successor.Verify(sessionContext); err != nil {
		return fmt.Errorf("native successor identity evidence: %w", err)
	}
	if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("native successor did not retain identity authority")
	}
	journal, err = disable.Load(sessionContext)
	if err != nil || journal.Phase != smbprovision.Disabled || journal.SID != sid {
		return errors.New("native live session disabled confirmation")
	}
	if err := backend.VerifyNativePeerSessionQEMU(sessionContext, pair); err != nil {
		return fmt.Errorf("native same peer session elapsed=%v context=%v: %w", time.Since(sessionStarted), sessionContext.Err(), err)
	}
	if err := runtime.VerifyNativeIdleDisableQEMU(sessionContext); err != nil {
		return fmt.Errorf("native revoked fresh login elapsed=%v context=%v: %w", time.Since(sessionStarted), sessionContext.Err(), err)
	}
	if err := runtime.StopNativeDaemonQEMU(context.Background()); err != nil {
		return err
	}
	for _, lease := range revocationLeases {
		if err := lease.Release(); err != nil {
			return err
		}
	}
	revocationLeases = nil
	// Use a fresh context so this tests the single-use lifecycle refusal rather
	// than cancellation of the already-completed authentication phase.
	if err := runtime.StartNativeDaemonQEMU(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("native stopped daemon restarted")
	}
	if err := owner.Close(); err != nil {
		return err
	}
	if err := runtime.Close(context.Background()); err != nil {
		return err
	}
	if err := nativeDataFixtureQEMU(plan, lookup); err != nil {
		return fmt.Errorf("native data descriptor profile: %w", err)
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		return errors.New("native credential descriptor leak")
	}
	nativeCredentialPreparationMarkersQEMU()
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_LIVE_REVOKE_READY accounts=2 qualified_pair=true owner_bound=true same_sid=true target_absent=true same_peer_session=true new_login_denied=true other_login_allowed=true same_daemon=true no_new_privileges=true stopped_reaped=true no_fd_leak=true scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_BACKEND_BINDING_READY owner_bound=true backend_bound=true unchanged_verified=true foreign_refused=true close_busy=true released_before_start=true release_no_mutation=true stopped_reaped=true no_fd_leak=true service_owner=false scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_DISABLE_HANDOFF_READY owner_bound=true backend_bound=true atomic_successor=true old_review=true new_verified=true close_busy=true same_peer_session=true retained_until_stop=true stopped_reaped=true no_fd_leak=true startup_bound=false service_owner=false scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_DATA_READY original_objects=true individual_clones=true readonly_EROFS=true smb_read=true smb_write=true unix_owner=true symlink_denied=true private_namespace=true stopped_before_release=true no_fd_leak=true complete_storage_identity=false scope=qemu-only")
	return nil
}

// Emitted only after each campaign's complete real work and parent FD census.
func nativeCredentialPreparationMarkersQEMU() {
	nativeCredentialEnrollmentMarkerQEMU()
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_DAEMON_READY accounts=2 same_code=true same_config=true same_state=true authenticated=true wrong_password_denied=true owned_group=true stopped_reaped=true no_fd_leak=true scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_IDLE_DISABLE_READY owner_bound=true same_sid=true stable_absence=true new_login_denied=true other_login_allowed=true same_daemon=true no_new_privileges=true stopped_reaped=true no_fd_leak=true scope=qemu-only")
}

func nativeCredentialEnrollmentMarkerQEMU() {
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY accounts=2 owner_bound=true original_config=true original_state=true disabled_first=true stdin_only=true same_sid=true explicit_enable=true stopped_reaped=true no_fd_leak=true scope=qemu-only")
}

// This read-only probe finishes and releases BEFORE daemon/client startup. It
// does not turn a snapshot lease into service authority or refresh one after
// an account mutation. The complete credential/start/revoke campaigns retain
// their existing independent budgets; the outer guest limit is unchanged.
func nativeIdentityBackendProbeQEMU(owner *identityowner.Owner, backend *smbexec.NativeBackendQEMU) (result error) {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	started := time.Now()
	evidence, err := owner.FileServiceSnapshot(ctx)
	if err != nil {
		return fmt.Errorf("native Owner final identity census elapsed=%v context=%v: %w", time.Since(started), ctx.Err(), err)
	}
	if len(evidence.Registry.Accounts) != 2 || len(evidence.Passdb) != 2 ||
		!evidence.Passdb[0].Observation.Present || !evidence.Passdb[1].Observation.Present ||
		evidence.Passdb[0].Observation.Disabled || evidence.Passdb[1].Observation.Disabled ||
		evidence.Passdb[0].Observation.SID == evidence.Passdb[1].Observation.SID {
		return errors.New("invalid native Owner final account observation")
	}
	foreign := &smbexec.NativeBackendQEMU{}
	if refused, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, foreign); refused != nil || !errors.Is(err, identityowner.ErrConflict) {
		if refused != nil {
			_ = refused.Release()
		}
		return errors.New("foreign native backend binding admitted")
	}
	consumer, err := owner.RetainSMBFileServiceSnapshot(ctx, evidence.Fingerprint, backend)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, consumer.Release()) }()
	if err := consumer.Verify(ctx); err != nil {
		return err
	}
	if err := owner.Close(); !errors.Is(err, identityowner.ErrBusy) {
		return errors.New("native bound consumer did not retain Owner")
	}
	if err := consumer.Release(); err != nil {
		return err
	}
	if err := consumer.Verify(ctx); !errors.Is(err, identityowner.ErrUnavailable) {
		return errors.New("released native bound consumer verified")
	}
	after, err := owner.FileServiceSnapshot(ctx)
	if err != nil || after.Fingerprint != evidence.Fingerprint {
		return errors.Join(errors.New("native binding probe changed identity evidence"), err)
	}
	return nil
}
