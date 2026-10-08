//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/fileserviceplan"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const plannedSourceFaultMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_SOURCE_FAULT_READY same_authorities=true same_daemon=true data_verified=true source_covered=true exclusive_supervision=true review_sticky=true stopped_reaped=true private_inputs=15 runtime_inputs_retained=true originals_busy=true cover_removed=true restoration_refused=true private_mount_namespace=true subprocess_disposal=true parent_fd_equal=true activation=false scope=qemu-only"

const plannedSourceFaultChildProofQEMU = "PHANTOWD_PLANNED_SOURCE_FAULT_CHILD_READY same_authorities=true same_daemon=true data_verified=true source_covered=true exclusive_supervision=true review_sticky=true stopped_reaped=true private_inputs=15 runtime_inputs_retained=true originals_busy=true cover_removed=true restoration_refused=true private_mount_namespace=true scope=qemu-subprocess-only\n"

func nativePlannedSourceFaultSubprocessQEMU() error {
	return nativePlannedFaultSubprocessQEMU("source")
}

func nativePlannedFaultSubprocessQEMU(fault string) error {
	commandName, proof := "native-planned-source-fault", plannedSourceFaultChildProofQEMU
	if fault == "exit" {
		commandName, proof = "native-planned-exit-fault", plannedExitFaultChildProofQEMU
	} else if fault != "source" {
		return errors.New("invalid fixed planned fault subprocess")
	}
	// NEW fixed fault action: preparation10/startup40/data20/supervision20.
	// Original identity-fault40 and guest180 budgets are unchanged. Neither
	// successful child output nor guest exit alone replaces parent FD/union checks.
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, "/usr/sbin/phantowd-runtime-bundle-probe", commandName)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C"}
	command.SysProcAttr = &syscall.SysProcAttr{Cloneflags: unix.CLONE_NEWNS}
	command.WaitDelay = 2 * time.Second
	var output nativeFaultOutput
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil || output.String() != proof {
		return fmt.Errorf("planned %s fault subprocess proof incomplete", fault)
	}
	return nil
}

func nativePlannedSourceFaultQEMU() error {
	return nativePlannedFaultQEMU("source")
}

func nativePlannedFaultQEMU(fault string) error {
	if fault != "source" && fault != "exit" {
		return errors.New("invalid fixed planned fault")
	}
	// Refuse hosts BEFORE any open of authority/storage or namespace mutation.
	if runtime.GOARCH != "arm" || os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("planned source fault requires disposable ARM guest")
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" {
		return errors.New("planned source fault model guard")
	}
	commandLine, err := os.ReadFile("/proc/cmdline")
	var fs unix.Statfs_t
	if err != nil || !strings.Contains(" "+string(commandLine)+" ", " phantowd_samba_ext4_fixture=1 ") ||
		unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC ||
		unix.Statfs("/etc", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return errors.New("planned source fault volatile fixture guard")
	}
	self, selfErr := os.Readlink("/proc/self/ns/mnt")
	parent, parentErr := os.Readlink(fmt.Sprintf("/proc/%d/ns/mnt", os.Getppid()))
	if selfErr != nil || parentErr != nil || self == parent {
		return errors.New("planned source fault requires separate mount namespace")
	}
	if err := unix.Mount("", "/", "", unix.MS_REC|unix.MS_PRIVATE, ""); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	const authority = "/run/phantowd-native-authority"
	inventory := func(context.Context) (serviceaccounts.Reservations, error) {
		return serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}}, nil
	}
	bootstrap, err := identityowner.Open(authority, inventory)
	if err != nil {
		return err
	}
	lookup, lookupErr := fileserviceplan.SambaEnrollmentLookupFromOwner(ctx, bootstrap)
	if err := errors.Join(lookupErr, bootstrap.Close()); err != nil {
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
	if err := ctx.Err(); err != nil {
		return err
	}
	// The guest's actual disabled-first enrollment precedes this NEW consumer;
	// no copied passdb, replacement SID, healthy fixture backend or lease refresh.
	return nativePlannedServiceFixtureQEMU(plan, lookup, authority, inventory, fault)
}

func qualifyPlannedSourceFaultQEMU(ctx context.Context, service *smbexec.NativePlannedServiceQEMU, native *runtimebundle.NativeSambaRuntimeQEMU, owner *identityowner.Owner, handoff *mountowner.ServiceHandoff) error {
	initial, err := service.Status()
	if err != nil || initial.State != "ready" || !initial.DataVerified || !initial.IdentityRetained || !initial.SharesRetained || initial.RuntimeClosed {
		return errors.New("planned source fault lacks original live access authority")
	}
	const target = "/srv/phantowd/volumes/qemu-native"
	fd, err := unix.Openat2(unix.AT_FDCWD, target, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	original, err := plannedFaultMountIdentityQEMU(fd)
	if err != nil {
		return err
	}
	loopCtx, cancelLoop := context.WithCancel(ctx)
	defer cancelLoop()
	completed := make(chan error, 1)
	go func() { completed <- service.Supervise(loopCtx, time.Second) }()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-completed:
			return errors.Join(errors.New("planned fault supervisor ended before complete scan"), err)
		case <-ctx.Done():
			cancelLoop()
			return errors.Join(ctx.Err(), <-completed)
		case <-ticker.C:
			status, err := service.Status()
			if err != nil {
				cancelLoop()
				return errors.Join(err, <-completed)
			}
			if status.Checks <= initial.Checks {
				continue
			}
			if err := service.Observe(ctx); !errors.Is(err, processowner.ErrBusy) {
				cancelLoop()
				return errors.Join(errors.New("planned fault supervisor lost exclusivity"), err, <-completed)
			}
			// Cover ONLY the already-qualified synthetic volume alias. All
			// original mounts, grant clones and pinned objects remain attached.
			// Never detach a grant or alter data/TDBs/devices to trigger loss.
			if err := unix.Mount("/run", target, "", unix.MS_BIND, ""); err != nil {
				cancelLoop()
				return errors.Join(err, <-completed)
			}
			covered, err := plannedFaultPathIdentityQEMU(target)
			var fs unix.Statfs_t
			retained, retainedErr := plannedFaultMountIdentityQEMU(fd)
			if err != nil || retainedErr != nil || covered == original || retained != original ||
				unix.Statfs(target, &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
				cancelLoop()
				return errors.Join(errors.New("planned fault source cover not witnessed"), err, retainedErr, <-completed)
			}
			select {
			case err := <-completed:
				if !errors.Is(err, runtimebundle.ErrReviewRequired) {
					return errors.Join(errors.New("planned source loss did not quarantine supervisor"), err)
				}
			case <-ctx.Done():
				cancelLoop()
				return errors.Join(ctx.Err(), <-completed)
			}
			for range 2 {
				stopped, err := native.ObservePlannedStopQEMU(ctx)
				status, statusErr := service.Status()
				if err != nil || !stopped.DaemonStopped || !stopped.InputsRetained || statusErr != nil ||
					status.State != "review-required" || !status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed ||
					!errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
					return errors.Join(errors.New("planned source fault lost stop or retained authority"), err, statusErr)
				}
			}
			// Remove exactly the observed cover, not the original mount/grants.
			current, err := plannedFaultPathIdentityQEMU(target)
			if err != nil || current != covered {
				return errors.Join(errors.New("planned fault cover identity changed"), err)
			}
			if err := unix.Unmount(target, 0); err != nil {
				return err
			}
			current, err = plannedFaultPathIdentityQEMU(target)
			if err != nil || current != original {
				return errors.Join(errors.New("planned fault original alias not restored"), err)
			}
			for _, operation := range []func(context.Context) error{service.Start, service.Observe, service.VerifyDataAccess} {
				if err := operation(ctx); !errors.Is(err, runtimebundle.ErrReviewRequired) {
					return errors.New("planned source restoration revived service")
				}
			}
			if err := service.Supervise(ctx, time.Second); !errors.Is(err, runtimebundle.ErrReviewRequired) {
				return errors.New("planned source restoration revived supervision")
			}
			status, err = service.Status()
			if err != nil || status.State != "review-required" || !status.IdentityRetained || !status.SharesRetained || status.RuntimeClosed ||
				!errors.Is(owner.Close(), identityowner.ErrBusy) || !errors.Is(handoff.Close(), mountowner.ErrHandoffBusy) {
				return errors.New("planned source restoration released original authority")
			}
			return nil // Fixed child exit disposes review, never product recovery.
		}
	}
}

func plannedFaultMountIdentityQEMU(fd int) ([4]uint64, error) {
	var st unix.Statx_t
	const mask = unix.STATX_TYPE | unix.STATX_INO | unix.STATX_MNT_ID_UNIQUE
	if err := unix.Statx(fd, "", unix.AT_EMPTY_PATH, mask, &st); err != nil || st.Mask&mask != mask || st.Mode&unix.S_IFMT != unix.S_IFDIR {
		return [4]uint64{}, errors.Join(errors.New("planned fault mount identity unavailable"), err)
	}
	return [4]uint64{st.Mnt_id, st.Ino, uint64(st.Dev_major), uint64(st.Dev_minor)}, nil
}

func plannedFaultPathIdentityQEMU(path string) ([4]uint64, error) {
	fd, err := unix.Openat2(unix.AT_FDCWD, path, &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return [4]uint64{}, err
	}
	defer unix.Close(fd)
	return plannedFaultMountIdentityQEMU(fd)
}
