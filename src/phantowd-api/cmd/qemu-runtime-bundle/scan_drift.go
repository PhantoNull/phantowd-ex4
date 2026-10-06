//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

// Test-only scheduling at a real later hash read, without a production hook,
// fake metadata or sleeps. The retained descriptor is already at EOF; the
// inspector's independent O_RDONLY descriptor is at offset zero. Merely
// observing offsets never changes them. Scheduling runs in the serialized
// fixture caller; this is not a /proc-based product identity provider.
type scanMutationContext struct {
	context.Context
	path   string
	mutate func() error
	fired  bool
	err    error
}

func (c *scanMutationContext) Err() error {
	if err := c.Context.Err(); err != nil {
		return err
	}
	if c.fired || c.err != nil {
		return nil
	}
	dir, err := os.Open("/proc/self/fd")
	if err != nil {
		c.err = err
		return nil
	}
	entries, readErr := dir.ReadDir(513)
	closeErr := dir.Close()
	if readErr != nil || closeErr != nil || len(entries) > 512 {
		c.err = errors.New("bounded hash scheduling census unavailable")
		return nil
	}
	for _, entry := range entries {
		fd, err := strconv.Atoi(entry.Name())
		if err != nil {
			continue
		}
		name, err := os.Readlink("/proc/self/fd/" + entry.Name())
		if err != nil || name != c.path {
			continue
		}
		flags, err := unix.FcntlInt(uintptr(fd), unix.F_GETFL, 0)
		if err != nil || flags&unix.O_PATH != 0 || flags&unix.O_ACCMODE != unix.O_RDONLY {
			continue
		}
		position, err := unix.Seek(fd, 0, unix.SEEK_CUR)
		if err == nil && position == 0 {
			c.fired = true
			c.err = c.mutate()
			break
		}
	}
	return nil
}

// Replace an already-hashed executable's INNER directory while a later file
// is about to be hashed. The original executable inode/bytes stay unchanged,
// and the top root metadata stays unchanged. Inspect's point-in-time result
// must not be confused with the Owner's original-path identity authority.
func ownerScanDriftFixtures(data []byte) error {
	for _, kind := range []string{"directory", "alias"} {
		if err := ownerScanDriftCase(data, kind); err != nil {
			return fmt.Errorf("mid-scan %s: %w", kind, err)
		}
	}
	fmt.Println("PHANTOWD_CODE_OWNER_SCAN_READY actual_later_hash=true same_bytes=true inner_directory_replaced=true alias_replaced=true point_in_time_controls=true original_paths_refused=true before_child=true restoration_not_retried=true scope=qemu-only")
	return nil
}

func ownerScanDriftCase(data []byte, kind string) (result error) {
	source := ownerFixtureBase + "/scan-source-" + kind
	view := ownerFixtureBase + "/scan-view-" + kind
	prior := ownerFixtureBase + "/scan-prior-" + kind
	const executable = "bin/a/fixture"
	const later = "bin/z/payload"
	for _, name := range []string{source, view, source + "/bin", source + "/bin/a", source + "/bin/z"} {
		if err := os.Mkdir(name, 0755); err != nil {
			return err
		}
	}
	payload := make([]byte, 4096)
	if err := errors.Join(os.WriteFile(source+"/"+executable, data, 0555), os.WriteFile(source+"/"+later, payload, 0444)); err != nil {
		return err
	}
	if err := os.Symlink("/"+executable, source+"/bin/alias"); err != nil {
		return err
	}
	plan, err := runtimebundle.NewPlan([]runtimebundle.File{
		{Path: executable, SHA256: sha256.Sum256(data), Size: int64(len(data)), Mode: 0555},
		{Path: later, SHA256: sha256.Sum256(payload), Size: int64(len(payload)), Mode: 0444},
	}, []runtimebundle.Alias{{Path: "bin/alias", Target: executable}})
	if err != nil {
		return err
	}
	if err := unix.Mount(source, view, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	defer func() { result = errors.Join(result, unix.Unmount(view, 0)) }()
	if err := unix.Mount("", view, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, ""); err != nil {
		return err
	}
	root, err := stageRoot(view)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, root.Close()) }()
	mutate := func() error {
		if kind == "alias" {
			if err := os.Rename(source+"/bin/alias", prior); err != nil {
				return err
			}
			return os.Symlink("/"+executable, source+"/bin/alias")
		}
		if err := os.Rename(source+"/bin/a", prior); err != nil {
			return err
		}
		if err := os.Mkdir(source+"/bin/a", 0755); err != nil {
			return err
		}
		return os.WriteFile(source+"/"+executable, data, 0555)
	}
	restore := func() error {
		if kind == "alias" {
			if err := os.Remove(source + "/bin/alias"); err != nil {
				return err
			}
			return os.Rename(prior, source+"/bin/alias")
		}
		if err := os.Remove(source + "/" + executable); err != nil {
			return err
		}
		if err := os.Remove(source + "/bin/a"); err != nil {
			return err
		}
		return os.Rename(prior, source+"/bin/a")
	}
	control := &scanMutationContext{Context: context.Background(), path: view + "/" + later, mutate: mutate}
	observation, err := plan.Inspect(control, root)
	if err != nil || !control.fired || control.err != nil || observation.Files != 2 || observation.Aliases != 1 {
		return errors.Join(errors.New("mid-scan byte-only control did not execute"), err, control.err)
	}
	if err := restore(); err != nil {
		return err
	}
	marker := ownerFixtureBase + "/control/scan-" + kind
	owner, err := plan.NewOwner(context.Background(), root, []processowner.MemberSpec{{Name: "scan-fixture", Process: processowner.Spec{
		Executable: "/" + executable, Args: []string{"owner-child", marker},
		RunAs: &processowner.Credentials{UID: 1801, GID: 1800},
		Ready: func(context.Context) (bool, error) {
			_, err := os.Stat(marker + ".ready")
			return err == nil, nil
		},
		ReadyTimeout: 10 * time.Second, ProbeInterval: 50 * time.Millisecond, StopTimeout: 5 * time.Second,
	}}})
	if err != nil {
		return err
	}
	defer func() {
		err := owner.Close(context.Background())
		if !errors.Is(err, runtimebundle.ErrReviewRequired) {
			result = errors.Join(result, errors.New("mid-scan review lost on verified close"), err)
		}
	}()
	drift := &scanMutationContext{Context: context.Background(), path: view + "/" + later, mutate: mutate}
	denied, err := owner.Start(drift)
	if !drift.fired || drift.err != nil || !errors.Is(err, runtimebundle.ErrReviewRequired) ||
		denied.State != processowner.StateReviewRequired || len(denied.Processes.Members) != 1 || denied.Processes.Members[0].Process.PID != 0 {
		return errors.Join(errors.New("mid-scan replacement not quarantined"), err, drift.err)
	}
	if _, err := os.Stat(marker + ".ready"); !errors.Is(err, os.ErrNotExist) {
		return errors.New("mid-scan replacement launched a child")
	}
	if err := restore(); err != nil {
		return err
	}
	if _, err := owner.Start(context.Background()); !errors.Is(err, runtimebundle.ErrReviewRequired) {
		return errors.New("restoration cleared mid-scan review")
	}
	// Deferred verified Owner close, fixture-root close and normal unmount run
	// in that order. Their errors prevent the caller's final DONE marker.
	return nil
}
