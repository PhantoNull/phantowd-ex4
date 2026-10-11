//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const pendingPeerExitMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PENDING_PEER_EXIT_READY original_connection=true actual_peer_stop=true connection_refused=true client_group_absent=true daemon_group_absent=true review_sticky=true inputs_retained=true namespaces_retained=true close_refused=true restart_refused=true local_object_unchanged=true subprocess_disposal=true parent_fd_equal=true smb_object_bound=false pending_io=false activation=false scope=qemu-only"
const pendingPeerExitChildProofQEMU = "PHANTOWD_PENDING_PEER_EXIT_CHILD_READY original_connection=true actual_peer_stop=true connection_refused=true client_group_absent=true daemon_group_absent=true review_sticky=true inputs_retained=true namespaces_retained=true close_refused=true restart_refused=true local_object_unchanged=true scope=qemu-subprocess-only\n"

type pendingPeerExitOutputQEMU struct{ buffer bytes.Buffer }

// Own Write and no ReadFrom: io.Copy must not bypass the bound.
func (b *pendingPeerExitOutputQEMU) Write(p []byte) (int, error) {
	if b.buffer.Len()+len(p) > 65536 {
		return 0, errors.New("pending peer exit output bound")
	}
	return b.buffer.Write(p)
}

func (b *pendingPeerExitOutputQEMU) String() string { return b.buffer.String() }

var pendingPeerExitTimingQEMU = regexp.MustCompile(`^PHANTOWD_DIAG_NATIVE_WORKER operation=(check|list|create|password|enable|disable|status|revoke) phase=(pre-admission|execution|settlement|post-admission) elapsed_ms=(0|[1-9][0-9]{0,5}) remaining_ms=(0|[1-9][0-9]{0,5}) parent_done=(true|false) failed=(true|false) cause=(none|deadline|canceled|mismatch|unavailable|other) qualifying=false scope=qemu-only$`)

func pendingPeerExitProofQEMU(output string) (string, error) {
	if len(output) > 65536 || !strings.HasSuffix(output, pendingPeerExitChildProofQEMU) {
		return "", errors.New("pending peer exit child proof incomplete")
	}
	telemetry := strings.TrimSuffix(output, pendingPeerExitChildProofQEMU)
	if telemetry == "" {
		return "", nil
	}
	rows := strings.Split(strings.TrimSuffix(telemetry, "\n"), "\n")
	if !strings.HasSuffix(telemetry, "\n") || len(rows) > 512 {
		return "", errors.New("pending peer exit child telemetry bound")
	}
	for _, row := range rows {
		if !pendingPeerExitTimingQEMU.MatchString(row) {
			return "", errors.New("pending peer exit child unexpected output")
		}
	}
	return telemetry, nil // Diagnostic-only; never substitute for the proof.
}

func nativePendingPeerExitSubprocessQEMU() error {
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/sbin/phantowd-runtime-bundle-probe", "native-pending-peer-exit-child")
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	command.WaitDelay = 2 * time.Second
	var output pendingPeerExitOutputQEMU
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil {
		return errors.New("pending peer exit child did not settle")
	}
	telemetry, err := pendingPeerExitProofQEMU(output.String())
	if err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	fmt.Print(telemetry)
	return nil
}

func nativePendingPeerExitChildQEMU() error {
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("pending peer exit requires disposable ARM guest")
	}
	commandLine, commandErr := os.ReadFile("/proc/cmdline")
	var fs unix.Statfs_t
	if commandErr != nil || !strings.Contains(" "+string(commandLine)+" ", " phantowd_samba_ext4_fixture=1 ") ||
		unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("pending peer exit volatile fixture guard")
	}
	self, err := os.Readlink("/proc/self/ns/mnt")
	parent, parentErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", os.Getppid()))
	if err != nil || parentErr != nil || self == parent {
		return errors.New("pending peer exit requires private mount namespace")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	owner, err := identityowner.Open("/run/phantowd-native-authority", inventory)
	if err != nil {
		return err
	}
	lookup, lookupErr := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, owner)
	if err := errors.Join(lookupErr, owner.Close()); err != nil {
		return err
	}
	files, aliases, err := inputs()
	if err != nil {
		return err
	}
	plan, err := runtimebundle.NewPlan(files, aliases)
	if err != nil {
		return err
	}
	if err := nativeDataFixtureModeQEMU(plan, lookup, true, true); err != nil {
		return err
	}
	for _, original := range pendingPeerExitOriginalsQEMU {
		if original == nil {
			return errors.New("pending peer exit original missing")
		}
		if _, err := original.Stat(); err != nil {
			return err
		}
	}
	if len(pendingPeerExitOriginalsQEMU) != 5 {
		return errors.New("pending peer exit originals incomplete")
	}
	fmt.Print(pendingPeerExitChildProofQEMU)
	return nil // Whole subprocess disposal, never healthy/recovery release.
}
