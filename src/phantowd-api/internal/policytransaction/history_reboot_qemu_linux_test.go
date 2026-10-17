//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

// Only stable, explicitly selected filesystem metadata crosses kernel boots.
// Mount IDs, device numbers, descriptors and process identities do not.
type historyRebootEntry struct {
	Name      string `json:"name"`
	Data      []byte `json:"data"`
	Inode     uint64 `json:"inode"`
	Mode      uint16 `json:"mode"`
	UID       uint32 `json:"uid"`
	GID       uint32 `json:"gid"`
	Links     uint32 `json:"links"`
	Size      uint64 `json:"size"`
	AtimeSec  int64  `json:"atime_sec"`
	AtimeNsec uint32 `json:"atime_nsec"`
	MtimeSec  int64  `json:"mtime_sec"`
	MtimeNsec uint32 `json:"mtime_nsec"`
	CtimeSec  int64  `json:"ctime_sec"`
	CtimeNsec uint32 `json:"ctime_nsec"`
}

type historyRebootProof struct {
	Version int                  `json:"version"`
	Phase   string               `json:"phase"`
	Nonce   string               `json:"nonce"`
	BootID  string               `json:"boot_id"`
	PID     int                  `json:"pid"`
	Root    string               `json:"root"`
	Entries []historyRebootEntry `json:"entries"`
}

func historyRebootEntries(refs *crashRefs, snapshot map[string][]byte) ([]historyRebootEntry, error) {
	if refs == nil || refs.verify() != nil || len(snapshot) != 3 || len(refs.extraFiles) != 2 {
		return nil, ErrReview
	}
	var entries []historyRebootEntry
	appendEntry := func(name string, data []byte, meta unix.Statx_t) {
		entries = append(entries, historyRebootEntry{name, data, meta.Ino, meta.Mode, meta.Uid, meta.Gid, meta.Nlink, meta.Size,
			meta.Atime.Sec, meta.Atime.Nsec, meta.Mtime.Sec, meta.Mtime.Nsec, meta.Ctime.Sec, meta.Ctime.Nsec})
	}
	for index, name := range []string{".", "policy", "operations"} {
		appendEntry(name, nil, refs.dirMeta[index])
	}
	appendEntry("policy/nas-services.json", snapshot["policy"], refs.files[0].meta)
	for name, file := range refs.extraFiles {
		appendEntry("operations/"+name, snapshot[name], file.meta)
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

// Test executable only: first boot creates fresh synthetic state; second boot
// can ONLY observe it. No product constructor, recovery, HTTP or service exists.
func RunHistoryRebootFixture(t *testing.T, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error) {
	t.Helper()
	line, err := os.ReadFile("/proc/cmdline")
	if err != nil || !strings.Contains(string(line), "phantowd_history_reboot_") {
		t.Skip("explicit synthetic two-boot fixture only")
	}
	r, err := decodeHistoryRebootRequest(string(line))
	if err != nil || probe == nil {
		t.Fatal("invalid closed reboot request")
	}
	requireObserverMedia(t, r.phase == "observe")
	boot, err := os.ReadFile("/proc/sys/kernel/random/boot_id")
	bootID := strings.TrimSpace(string(boot))
	if err != nil || !validHistoryBootID(bootID) || bootID == r.previous {
		t.Fatal("distinct kernel boot identity unavailable")
	}
	read, write, err := os.Pipe()
	if err != nil || read.Close() != nil || write.Close() != nil {
		t.Fatal("reboot poller warmup")
	}
	baseline, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("reboot descriptor baseline")
	}
	root := r.root
	if r.phase == "produce" {
		root = runHistoryMediaChild(t, "produce", "")
		if err := unix.Mount("", historyExt4Root, "", unix.MS_REMOUNT|unix.MS_RDONLY|observerMediaRestrictions, ""); err != nil {
			t.Fatal("producer RO observation remount", err)
		}
	}
	requireObserverMedia(t, true)
	refs, err := captureRefsProfile(root, unix.EXT4_SUPER_MAGIC, true)
	if err != nil {
		if refs != nil {
			_ = refs.releaseReferences()
		}
		t.Fatal("reboot complete protected capture")
	}
	closed := false
	defer func() {
		if !closed && refs.releaseReferences() != nil {
			t.Error("reboot capture closure")
		}
	}()
	before, err := refs.historySnapshot()
	if err != nil {
		t.Fatal("reboot original bytes")
	}
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal("independent synthetic checkpoint")
	}
	checkpoint, err := json.Marshal(c)
	if err != nil {
		t.Fatal("synthetic checkpoint encoding")
	}
	fixtureRevision(&c, 3)
	expected, err := json.Marshal(c)
	if err != nil || !bytes.Equal(before["policy"], expected) {
		t.Fatal("reboot expected revision3 differs")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if probe(ctx, root, checkpoint, false, policyevidence.LocalConfirmationObserved) != nil || refs.verify() != nil {
		t.Fatal("reboot actual history observation")
	}
	after, err := refs.historySnapshot()
	if err != nil || !reflect.DeepEqual(before, after) {
		t.Fatal("reboot observation changed evidence")
	}
	entries, err := historyRebootEntries(refs, before)
	if err != nil {
		t.Fatal("reboot stable metadata capture")
	}
	closed = true // Once-only closure; never retry after an uncertain result.
	if refs.releaseReferences() != nil {
		t.Fatal("reboot verified capture closure")
	}
	end, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(end) != len(baseline) {
		t.Fatal("reboot descriptor baseline changed")
	}
	proof, err := json.Marshal(historyRebootProof{1, r.phase, r.nonce, bootID, os.Getpid(), root, entries})
	if err != nil || len(proof) > 32768 {
		t.Fatal("bounded reboot proof encoding")
	}
	// Invented fixture bytes only. Parent independently checks both complete
	// boot receipts and compares exact bytes/metadata; never product provenance.
	if _, err := fmt.Printf("PHANTOWD_HISTORY_REBOOT_RECORD %s\n", proof); err != nil {
		t.Fatal("reboot proof publication")
	}
}
