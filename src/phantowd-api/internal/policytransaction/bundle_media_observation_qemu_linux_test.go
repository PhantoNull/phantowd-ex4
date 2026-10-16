//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

const observerMediaRoot = "/run/phantowd-revisionstore-media"
const observerMediaRestrictions = unix.MS_NOSUID | unix.MS_NODEV | unix.MS_NOEXEC

func requireObserverMedia(t *testing.T, readOnly bool) {
	t.Helper()
	if runtime.GOARCH != "arm" {
		t.Skip("dedicated synthetic ARM guest only")
	}
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || len(line) > 4096 {
		t.Fatal("fixture command line unavailable")
	}
	markers := 0
	for _, field := range strings.Fields(string(line)) {
		if field == "phantowd_revisionstore_media_fixture=1" {
			markers++
		}
	}
	model, err := os.ReadFile("/sys/firmware/devicetree/base/model")
	if err != nil || len(model) > 128 || strings.TrimRight(string(model), "\x00") != "ARM Versatile PB" || markers != 1 || os.Geteuid() != 0 || os.Getenv("TMPDIR") != observerMediaRoot {
		t.Fatal("not the fixed disposable observer media fixture")
	}
	var fs unix.Statfs_t
	var root, device unix.Stat_t
	flags := int64(unix.ST_NOSUID | unix.ST_NODEV | unix.ST_NOEXEC)
	if readOnly {
		flags |= unix.ST_RDONLY
	}
	if unix.Statfs(observerMediaRoot, &fs) != nil || fs.Type != unix.EXT4_SUPER_MAGIC || int64(fs.Flags)&(unix.ST_NOSUID|unix.ST_NODEV|unix.ST_NOEXEC|unix.ST_RDONLY) != flags ||
		fs.Bsize <= 0 || fs.Blocks*uint64(fs.Bsize) > 32<<20 || fs.Blocks*uint64(fs.Bsize) < 8<<20 ||
		unix.Lstat(observerMediaRoot, &root) != nil || root.Mode&unix.S_IFMT != unix.S_IFDIR || root.Uid != 0 || root.Gid != 0 ||
		unix.Stat("/dev/sdb", &device) != nil || device.Mode&unix.S_IFMT != unix.S_IFBLK || root.Dev != device.Rdev {
		t.Fatal("fixed bounded synthetic ext4 mount unavailable")
	}
}

// RunReadOnlyBundleMediaFixture is present only in the Go test binary. It
// prepares invented evidence before a verified read-only remount; no product
// writer/provisioning path is opened. The callback must close its observer.
func RunReadOnlyBundleMediaFixture(t *testing.T, probe func(context.Context, string, bool, policyevidence.Kind) error) {
	t.Helper()
	if probe == nil {
		t.Fatal("missing runtime observation probe")
	}
	requireObserverMedia(t, false)
	beforeFDs, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("original descriptor baseline unavailable")
	}
	b, next, _ := fixture(t)
	defer b.clear()
	confirmed, err := confirmedBundle(b)
	if err != nil {
		t.Fatal("fixture confirmation declaration")
	}
	defer confirmed.clear()
	intentWire, _ := json.Marshal(b)
	confirmedWire, _ := json.Marshal(confirmed)
	cases := []struct {
		name               string
		current, operation []byte
		pending            string
		want               policyevidence.Kind
	}{
		{"no-operation", next, nil, "", policyevidence.NoRecordedOperation},
		{"base", b.base, intentWire, "", policyevidence.IntentBaseObserved},
		{"published", next, intentWire, "", policyevidence.PublicationUnconfirmed},
		{"confirmed", next, confirmedWire, "", policyevidence.LocalConfirmationObserved},
		{"inconsistent", b.base, confirmedWire, "", policyevidence.InconsistentEvidence},
		{"missing-current", nil, confirmedWire, "", policyevidence.IncompleteEvidence},
		{"policy-pending", next, confirmedWire, "policy/.nas-services.pending", ""},
		{"operation-pending", next, confirmedWire, "operations/.operation.pending", ""},
	}
	type retained struct {
		root   string
		refs   *crashRefs
		before [2][]byte
	}
	var all []retained
	defer func() {
		// Close each original exactly once; test TempDir cleanup runs only after
		// the later remount defer has restored this synthetic filesystem.
		for _, r := range all {
			for _, f := range r.refs.files {
				if f.f != nil && f.f.Close() != nil {
					t.Error("original file close uncertain")
				}
			}
			for _, d := range r.refs.dirs {
				if d != nil && d.Close() != nil {
					t.Error("original directory close uncertain")
				}
			}
		}
		afterFDs, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(afterFDs) != len(beforeFDs) {
			t.Error("descriptor count did not return to baseline")
		}
	}()
	for _, tc := range cases {
		root := t.TempDir()
		if filepath.Dir(filepath.Dir(root)) != observerMediaRoot || os.Chmod(root, 0700) != nil {
			t.Fatal("fixture root escaped bounded media")
		}
		for _, child := range []string{"policy", "operations"} {
			if os.Mkdir(filepath.Join(root, child), 0700) != nil {
				t.Fatal("fixture directory")
			}
		}
		for name, data := range map[string][]byte{"policy/nas-services.json": tc.current, "operations/operation.json": tc.operation} {
			if data != nil && os.WriteFile(filepath.Join(root, name), data, 0600) != nil {
				t.Fatal("fixture document")
			}
		}
		if tc.pending != "" && os.WriteFile(filepath.Join(root, tc.pending), []byte("malformed unpromoted staged evidence"), 0600) != nil {
			t.Fatal("fixture pending")
		}
		refs, err := captureRefsForFilesystem(root, unix.EXT4_SUPER_MAGIC)
		if refs != nil {
			all = append(all, retained{root: root, refs: refs})
		}
		if err != nil {
			t.Fatal("original media capture refused")
		}
		before, err := refs.snapshot()
		if err != nil {
			t.Fatal("original media snapshot refused")
		}
		all[len(all)-1].before = before
	}
	if unix.Mount("", observerMediaRoot, "", unix.MS_REMOUNT|unix.MS_RDONLY|observerMediaRestrictions, "") != nil {
		t.Fatal("synthetic read-only remount failed")
	}
	defer func() {
		if unix.Mount("", observerMediaRoot, "", unix.MS_REMOUNT|observerMediaRestrictions, "") != nil {
			t.Error("synthetic mount restoration failed")
		}
	}()
	requireObserverMedia(t, true)
	for i, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			r := all[i]
			if r.refs.verify() != nil || probe(ctx, r.root, tc.pending != "", tc.want) != nil || r.refs.verify() != nil {
				t.Fatal("read-only media runtime diagnosis refused or changed evidence")
			}
			after, err := r.refs.snapshot()
			if err != nil || !reflect.DeepEqual(r.before, after) {
				t.Fatal("read-only diagnosis changed bytes or metadata")
			}
			requireObserverMedia(t, true)
		})
	}
}
