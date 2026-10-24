//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"golang.org/x/sys/unix"
)

func TestQEMUNFSConfigurationRetainsOnlyFixedReadonlyData(t *testing.T) {
	model, _ := os.ReadFile("/sys/firmware/devicetree/base/model")
	cmdline, _ := os.ReadFile("/proc/cmdline")
	if string(model) != "ARM Versatile PB\x00" || os.Getuid() != 0 || os.Geteuid() != 0 || os.Getgid() != 0 || os.Getegid() != 0 ||
		!slices.Contains(strings.Fields(string(cmdline)), "phantowd_nfs_inputs_fixture=1") {
		t.Skip("requires the explicitly guarded networkless NFS input guest")
	}
	var fs unix.Statfs_t
	if os.Getenv("TMPDIR") != "/run" || unix.Statfs("/run", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		t.Fatal("configuration fixture requires prepared RAM scratch")
	}
	candidate := nfsDocumentCandidate(t, []nfsconfig.Export{nfsDocumentExport()})
	enabled, plan, err := nfsConfigurationPlan(candidate)
	if err != nil || !enabled || plan == nil {
		t.Fatal("NFS configuration expectations", err)
	}
	_, documents, _ := NFSv3Documents(candidate)
	a, b, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := errors.Join(a.Close(), b.Close()); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []string{"", "etc/nfs.conf.d/extra.conf", "usr/etc/nfs.conf"} {
		t.Run("extra="+extra, func(t *testing.T) {
			directory := t.TempDir()
			if err := unix.Mount("tmpfs", directory, "tmpfs", unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "mode=0755,size=128k"); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				if err := unix.Unmount(directory, 0); err != nil {
					t.Error(err)
				}
			})
			write := func(name, value string, mode os.FileMode) {
				t.Helper()
				name = filepath.Join(directory, name)
				if err := os.MkdirAll(filepath.Dir(name), 0755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(name, []byte(value), mode); err != nil {
					t.Fatal(err)
				}
			}
			for name, value := range documents {
				mode := os.FileMode(0600)
				if name == "etc/netconfig" {
					mode = 0644
				}
				write(name, value, mode)
			}
			if extra != "" {
				write(extra, "undeclared configuration\n", 0644)
			}
			if err := unix.Mount("", directory, "tmpfs", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, ""); err != nil {
				t.Fatal(err)
			}
			fd, err := unix.Open(directory, unix.O_PATH|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
			if err != nil {
				t.Fatal(err)
			}
			root := os.NewFile(uintptr(fd), "disposable-nfs-configuration")
			defer root.Close()
			before, err := retainedFixtureFDCount()
			if err != nil {
				t.Fatal(err)
			}
			caller, err := duplicateRoot(root)
			if err != nil {
				t.Fatal(err)
			}
			held, retainErr := plan.retain(context.Background(), caller)
			if err := caller.Close(); err != nil {
				t.Fatal(err)
			}
			if held != nil {
				defer held.release()
			}
			if extra != "" {
				if held != nil || retainErr == nil {
					t.Fatal("undeclared fallback/fragment was admitted")
				}
			} else {
				if retainErr != nil {
					t.Fatal("fixed readonly configuration refused", retainErr)
				}
				if err := held.revalidate(context.Background()); err != nil {
					t.Fatal(err)
				}
				if err := held.release(); err != nil {
					t.Fatal(err)
				}
				if !errors.Is(held.revalidate(context.Background()), ErrUnavailable) {
					t.Fatal("released configuration remained usable")
				}
			}
			if _, err := root.Stat(); err != nil {
				t.Fatal("caller root was consumed", err)
			}
			if after, err := retainedFixtureFDCount(); err != nil || after != before {
				t.Fatal("configuration descriptor census changed", err)
			}
		})
	}
}
