//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// Failure retains the original fixture objects until this disposable process
// exits; it is not a product quarantine, recovery or daemon launcher.
var nfsLoaderProbeRetainedQEMU any

func probeNFSLoaderQEMU(ctx context.Context, code *NFSCodeQEMU) (result error) {
	s, err := code.enter(ctx)
	if err != nil {
		return err
	}
	defer s.leave()
	var child *processowner.IsolatedOwner
	defer func() {
		if result != nil {
			s.review, s.cause = true, result
			nfsLoaderProbeRetainedQEMU = struct {
				code  *NFSCodeQEMU
				child *processowner.IsolatedOwner
				err   error
			}{code, child, result}
		}
	}()
	if s.review || s.closed || s.revalidate(ctx) != nil {
		return ErrReviewRequired
	}
	before, err := retainedFixtureFDCount()
	if err != nil {
		return err
	}
	const ready = "PHANTOWD_NFS_LOADER_CHILD_READY\n"
	spec := processowner.Spec{
		Executable: "/usr/sbin/phantowd-nfs-code-fixture", Args: []string{"--loader-observer"},
		RunAs:        &processowner.Credentials{UID: 1000, GID: 1000},
		ReadyTimeout: 20 * time.Second, ProbeInterval: 20 * time.Millisecond, StopTimeout: time.Second,
		Ready: func(ctx context.Context) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			text := string(child.Diagnostics())
			return strings.HasSuffix(text, ready) && strings.Count(text, ready) == 1, nil
		},
	}
	child, err = processowner.NewIsolated(spec, processowner.Isolation{
		LauncherExecutable: "/usr/sbin/phantowd-service-launcher", Root: s.code.root,
	})
	if err != nil {
		return err
	}
	started, err := child.Start(ctx)
	if err != nil {
		return err // Retain original Owner; no blind stop/close retry.
	}
	// Every path after successful start attempts stop ONCE before returning.
	checkErr := func() error {
		if started.State != processowner.StateReady || started.Generation != 1 || started.PID <= 0 || started.DiagnosticsTruncated {
			return ErrMismatch
		}
		var namespace, root unix.Stat_t
		if unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", started.PID), &namespace) != nil || namespace.Ino == s.ns.Ino ||
			unix.Stat(fmt.Sprintf("/proc/%d/root", started.PID), &root) != nil {
			return ErrMismatch
		}
		original := s.code.metadata["."]
		if root.Ino != original.Ino || unix.Major(uint64(root.Dev)) != original.Dev_major || unix.Minor(uint64(root.Dev)) != original.Dev_minor {
			return ErrMismatch
		}
		return s.revalidate(ctx)
	}()
	cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	stopped, stopErr := child.Stop(cleanup)
	cancel()
	if stopErr != nil || stopped.State != processowner.StateStopped || stopped.Generation != 1 || stopped.PID != 0 || stopped.DiagnosticsTruncated ||
		!errors.Is(unix.Kill(-started.PID, 0), unix.ESRCH) {
		return errors.Join(ErrReviewRequired, checkErr, stopErr)
	}
	if checkErr != nil {
		return checkErr // Verified stop, but original code/Owner still retained.
	}
	text := string(child.Diagnostics())
	if !strings.HasSuffix(text, ready) || strings.Count(text, ready) != 1 || len(text) > 16<<10 {
		return ErrMismatch
	}
	if err := child.Close(); err != nil {
		return err
	}
	if err := s.revalidate(ctx); err != nil {
		return err
	}
	if after, err := retainedFixtureFDCount(); err != nil || after != before {
		return ErrMismatch
	}
	// Raw fixed public dependency names are guest-test evidence only. The host
	// independently compares each complete list to its own build expectations.
	fmt.Print(strings.TrimSuffix(text, ready))
	fmt.Println("PHANTOWD_NFS_LOADER_READY nonroot=true capabilities_zero=true root_restricted=true private_namespace=true original_code=true stop_reaped=true fd_balance=true entrypoints=false scope=qemu-only")
	return nil
}
