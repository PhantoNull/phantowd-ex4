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

func nativeCredentialFixture() (result error) {
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
	for _, confirmed := range native {
		op := owner.SMB(confirmed.Account.ID)
		if err := op.Begin(ctx, confirmed.Revision); err != nil {
			return fmt.Errorf("native enrollment begin: %w", err)
		}
		journal, err := op.Load(ctx)
		if err != nil || journal.Phase != smbprovision.Reserved {
			return errors.New("native enrollment intent")
		}
		if err := op.Step(ctx, journal.Revision); err != nil {
			return fmt.Errorf("native disabled creation: %w", err)
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
	observed, err := backend.ObserveAccounts(ctx, registry.Accounts)
	if err != nil || len(observed) != 2 || observed[0].Disabled || observed[1].Disabled ||
		!observed[0].Present || !observed[1].Present || observed[0].SID == observed[1].SID {
		return errors.Join(errors.New("native backend final identity census"), err)
	}
	// Authentication is a new, separately bounded phase; the original 60-second
	// credential campaign remains unchanged. The outer guest still has 180s.
	daemonContext, stopDaemonContext := context.WithTimeout(context.Background(), 20*time.Second)
	defer stopDaemonContext()
	if err := runtime.ProbeNativeDaemonQEMU(daemonContext); err != nil {
		return fmt.Errorf("native same-state daemon: %w", err)
	}
	if err := owner.Close(); err != nil {
		return err
	}
	if err := runtime.Close(context.Background()); err != nil {
		return err
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		return errors.New("native credential descriptor leak")
	}
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_ENROLLMENT_READY accounts=2 owner_bound=true original_config=true original_state=true disabled_first=true stdin_only=true same_sid=true explicit_enable=true stopped_reaped=true no_fd_leak=true scope=qemu-only")
	fmt.Println("PHANTOWD_SAMBA_OWNER_NATIVE_DAEMON_READY accounts=2 same_code=true same_config=true same_state=true authenticated=true wrong_password_denied=true owned_group=true stopped_reaped=true no_fd_leak=true scope=qemu-only")
	return nil
}
