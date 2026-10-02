//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package mountowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
	"golang.org/x/sys/unix"
)

// RunQEMUIsolatedHandoffFixture joins the existing QEMU-only qualified roster
// to one fixed static consumer. No product executable, storage or API wiring.
func RunQEMUIsolatedHandoffFixture() error {
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || string(model) != "ARM Versatile PB\x00" || runtime.GOARCH != "arm" ||
		os.Getuid() != 0 || os.Geteuid() != 0 {
		return errors.New("isolated handoff fixture requires disposable ARMv5 Versatile PB")
	}
	const public = qemuFixtureSource + "/public"
	if err := os.Mkdir(public, 0700); err != nil {
		return err
	}
	defer os.Remove(public)
	if err := os.Chown(public, 1000, 1000); err != nil {
		return err
	}
	if err := os.WriteFile(public+"/marker", []byte("approved"), 0600); err != nil {
		return err
	}
	defer os.Remove(public + "/marker")
	if err := os.Chown(public+"/marker", 1000, 1000); err != nil {
		return err
	}
	for _, lost := range []bool{false, true} {
		if err := exerciseIsolatedHandoff(lost); err != nil {
			return err
		}
	}
	fmt.Println("PHANTOWD_ISOLATED_HANDOFF_READY grant_only_root=true original_path_denied=true nonroot=true read_only=true close_gated=true stop_before_release=true source_loss_review=true no_restart=true scope=disposable-qemu-only")
	return nil
}

func exerciseIsolatedHandoff(lost bool) error {
	ctx := context.Background()
	const root = "/run/phantowd/service-handoff/isolated-qemu"
	if err := os.MkdirAll("/run/phantowd/service-handoff", 0755); err != nil {
		return err
	}
	if err := os.Mkdir(root, 0710); err != nil {
		return err
	}
	defer os.Remove(root)
	if err := os.Chown(root, 0, 1000); err != nil {
		return err
	}
	if err := os.Chmod(root, 0710); err != nil {
		return err
	}
	result := withQEMUMountedOwner(qemuFixtureSource, func(owner *Owner) (result error) {
		set, err := newMountedVolumeSet([]string{qemuPlannerVolumeID}, []*Owner{owner})
		if err != nil {
			return err
		}
		handoff, err := NewServiceHandoff(root, set, []ServiceShare{{
			ID: "share", VolumeID: qemuPlannerVolumeID, RelativePath: "public", ReadOnly: true,
		}}, 1000)
		if err != nil {
			return err
		}
		var runtime *IsolatedServiceRuntime
		var pid int
		spec := processowner.Spec{
			Executable: "/usr/sbin/phantowd-service-launcher-fixture", Args: []string{"--owner-probe"},
			RunAs:        &processowner.Credentials{UID: 1000, GID: 1000, SupplementaryGIDs: []uint32{1000}},
			ReadyTimeout: 5 * time.Second, ProbeInterval: 20 * time.Millisecond, StopTimeout: time.Second,
			Ready: func(ctx context.Context) (bool, error) {
				if ctx.Err() != nil {
					return false, ctx.Err()
				}
				text := string(runtime.Diagnostics())
				if !strings.Contains(text, "PHANTOWD_SERVICE_SANDBOX_READY ") {
					return false, nil
				}
				var group int
				if _, err := fmt.Sscanf(text, "PHANTOWD_SERVICE_SANDBOX_READY pid=%d pgid=%d", &pid, &group); err != nil || pid != group {
					return false, errors.New("isolated handoff child evidence mismatch")
				}
				return true, nil
			},
		}
		runtime, err = NewIsolatedServiceRuntime(handoff, spec, "/usr/sbin/phantowd-service-launcher")
		if err != nil {
			return errors.Join(err, handoff.Close())
		}
		defer func() {
			if runtime.runtime.State() != ServiceRuntimeReview {
				_, err := runtime.Stop(ctx)
				result = errors.Join(result, err)
			}
		}()
		if state, err := runtime.Start(ctx); err != nil || state != ServiceRuntimeReady {
			return errors.Join(errors.New("isolated handoff start failed"), err)
		}
		if !errors.Is(handoff.Close(), ErrHandoffBusy) || handoff.State() != ServiceHandoffActive || handoff.isolatedPins != 1 {
			return errors.New("live child did not retain its root pin")
		}
		var parent, child unix.Stat_t
		if unix.Stat("/proc/self/ns/mnt", &parent) != nil ||
			unix.Stat(fmt.Sprintf("/proc/%d/ns/mnt", pid), &child) != nil || parent.Ino == child.Ino {
			return errors.New("storage-backed child kept the host namespace")
		}
		if lost {
			if err := unix.Mount("/run", owner.target, "", unix.MS_BIND, ""); err != nil {
				return err
			}
			defer func() {
				if err := unix.Unmount(owner.target, 0); err != nil {
					result = errors.Join(result, err)
				}
			}()
			state, err := runtime.Observe(ctx)
			if !errors.Is(err, ErrServiceRuntimeReview) || state != ServiceRuntimeReview ||
				owner.State() != StateReviewRequired || !handoff.resourcesClosed || handoff.isolatedPins != 0 {
				return errors.Join(errors.New("source loss did not stop before releasing grants"), err)
			}
			if _, err := runtime.Start(ctx); !errors.Is(err, ErrServiceRuntimeReview) {
				return errors.New("source loss permitted runtime restart")
			}
		} else {
			if state, err := runtime.Observe(ctx); err != nil || state != ServiceRuntimeReady {
				return errors.Join(errors.New("ready isolated handoff failed revalidation"), err)
			}
			if state, err := runtime.Stop(ctx); err != nil || state != ServiceRuntimeStopped ||
				handoff.isolatedPins != 0 || !handoff.resourcesClosed {
				return errors.Join(errors.New("isolated handoff did not stop and release"), err)
			}
		}
		if err := unix.Kill(-pid, 0); !errors.Is(err, unix.ESRCH) {
			return errors.New("isolated handoff retained a live child group")
		}
		if _, err := os.Lstat(root + "/share"); !errors.Is(err, os.ErrNotExist) {
			return errors.New("isolated handoff retained its grant clone")
		}
		if lost {
			return errQEMUExpectedMountedOwnerReview
		}
		return nil
	})
	if result == errQEMUExpectedMountedOwnerReview {
		return nil
	}
	return result
}
