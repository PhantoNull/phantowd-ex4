//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

func newDisposableHistoryOnExt4(ctx context.Context, id string, initial naspolicy.Config) (*writer, error) {
	return newDisposableOnMedium(ctx, id, initial, nil, true, nil, disposableFixedExt4)
}

func TestHistoryExt4ConstructorRefusesOrdinaryHost(t *testing.T) {
	if runtime.GOARCH == "arm" {
		t.Skip("ordinary native host refusal only")
	}
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	if w, err := newDisposableOnMedium(context.Background(), testInstallation, c, nil, true, nil, disposableMedium(255)); w != nil || err != ErrInvalid {
		t.Fatal("unknown medium admitted")
	}
	if w, err := newDisposableOnMedium(context.Background(), testInstallation, c, nil, false, nil, disposableFixedExt4); w != nil || err != ErrInvalid {
		t.Fatal("legacy writer silently widened")
	}
	if w, err := newDisposableHistoryOnExt4(context.Background(), testInstallation, c); w != nil || err != ErrUnsupported {
		t.Fatal("unmarked host reached media construction", err)
	}
}

func RunHistoryWriterMediaFixture(t *testing.T, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error) {
	t.Helper()
	if probe == nil {
		t.Fatal("missing history media probe")
	}
	requireObserverMedia(t, false)
	for _, scenario := range []string{"normal", "readonly", "full"} {
		t.Run(scenario, func(t *testing.T) { historyMediaScenario(t, scenario, probe) })
	}
	t.Run("process-boundary", func(t *testing.T) { historyMediaProcessBoundary(t, probe) })
}

func historyMediaScenario(t *testing.T, scenario string, probe func(context.Context, string, []byte, bool, policyevidence.Kind) error) {
	t.Helper()
	requireObserverMedia(t, false)
	beforeFDs, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal("media FD baseline")
	}
	c, err := naspolicy.Decode(strings.NewReader(testPolicy))
	if err != nil {
		t.Fatal(err)
	}
	checkpoint, _ := json.Marshal(c)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	w, err := newDisposableHistoryOnExt4(ctx, testInstallation, c)
	if err != nil {
		if w != nil {
			_ = w.close()
		}
		t.Fatal("fixed history medium construction", err)
	}
	var first, latest *crashRefs
	defer func() {
		if first != nil && first.releaseReferences() != nil {
			t.Error("media first references")
		}
		if latest != nil && latest.releaseReferences() != nil {
			t.Error("media latest references")
		}
		if w.close() != nil || w.discard() != nil {
			t.Error("media writer known-name closure/disposal")
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(after) != len(beforeFDs) {
			t.Error("media FD baseline changed")
		}
	}()
	fixtureRevision(&c, 2)
	if out, err := w.executeHistory(ctx, c); err != nil || out.revision != 2 || !actualLocksHeld(w) {
		t.Fatal("first ext4 history publication", err)
	}
	first, err = captureRefsProfile(w.path, unix.EXT4_SUPER_MAGIC, true)
	if err != nil {
		t.Fatal("first ext4 references")
	}
	before, err := first.historySnapshot()
	if err != nil {
		t.Fatal("first ext4 snapshot")
	}
	fixtureRevision(&c, 3)
	c.FileServices.Shares.Shares[0].RelativePath, c.FileServices.NFS.Exports[0].RelativePath = "after-books", "after-books"
	c.FileServices.Shares.Shares[0].Grants[0].Access = "ro"
	c.ISCSI.Targets[0].State = "enabled"
	var restore func()
	if scenario == "readonly" {
		if unix.Mount("", observerMediaRoot, "", unix.MS_REMOUNT|unix.MS_RDONLY|observerMediaRestrictions, "") != nil {
			t.Fatal("history readonly remount")
		}
		restore = func() {
			if unix.Mount("", observerMediaRoot, "", unix.MS_REMOUNT|observerMediaRestrictions, "") != nil {
				t.Error("history readonly restoration")
			}
		}
		defer func() {
			if restore != nil {
				restore()
			}
		}()
		requireObserverMedia(t, true)
		// Do not qualify merely an early model check: guards still admit the
		// retained lifetime, and an independent real create returns EROFS.
		if w.guard(ctx) != nil || w.history.check() != nil {
			t.Fatal("readonly failed before actual filesystem attempt")
		}
		f, err := os.OpenFile(filepath.Join(observerMediaRoot, "history-readonly-witness"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if f != nil {
			_ = f.Close()
			_ = os.Remove(filepath.Join(observerMediaRoot, "history-readonly-witness"))
			t.Fatal("readonly create succeeded")
		}
		if !errors.Is(err, unix.EROFS) {
			t.Fatal("real EROFS not observed", err)
		}
	} else if scenario == "full" {
		restore = fillHistoryMedia(t)
		defer func() {
			if restore != nil {
				restore()
			}
		}()
		if w.guard(ctx) != nil || w.history.check() != nil {
			t.Fatal("full medium failed before actual publication attempt")
		}
	}
	out, writeErr := w.executeHistory(ctx, c)
	if scenario == "normal" {
		if writeErr != nil || out.revision != 3 || w.review || len(w.history.records) != 2 {
			t.Fatal("second ext4 publication", writeErr)
		}
	} else if !errors.Is(writeErr, ErrReview) || out.revision != 0 || !w.review {
		t.Fatal("real media failure admitted", writeErr)
	}
	if !actualLocksHeld(w) {
		t.Fatal("media review released original lock")
	}
	latest, err = captureRefsProfile(w.path, unix.EXT4_SUPER_MAGIC, true)
	if err != nil || !firstHistoryStillOriginal(first, latest, before) {
		t.Fatal("media failure replaced first original")
	}
	frozen, err := latest.historySnapshot()
	if err != nil {
		t.Fatal("media result snapshot")
	}
	if scenario != "normal" && !bytes.Equal(frozen["policy"], before["policy"]) {
		t.Fatal("media failure changed confirmed policy")
	}
	if restore != nil {
		restore()
		restore = nil
	}
	requireObserverMedia(t, false)
	if scenario != "normal" {
		for range 2 {
			if out, err := w.executeHistory(ctx, c); err != ErrReview || out.revision != 0 {
				t.Fatal("restored medium admitted retry")
			}
		}
		if latest.verify() != nil {
			t.Fatal("retry changed media evidence")
		}
		after, err := latest.historySnapshot()
		if err != nil || !reflect.DeepEqual(frozen, after) {
			t.Fatal("retry changed stored bytes")
		}
	}
	if w.close() != nil {
		t.Fatal("media verified writer close")
	}
	_, policyPending := latest.names[0][".nas-services.pending"]
	_, historyPending := latest.names[1][journalPending]
	pending := policyPending || historyPending
	want := policyevidence.LocalConfirmationObserved
	if pending {
		want = ""
	}
	if latest.verify() != nil || probe(ctx, w.path, checkpoint, pending, want) != nil || latest.verify() != nil || !firstHistoryStillOriginal(first, latest, before) {
		t.Fatal("media runtime diagnosis changed retained evidence")
	}
	// Matching old receipt after failed create remains diagnosis only. The
	// original reviewed writer never resumed; no existing-state opener is used.
}

func fillHistoryMedia(t *testing.T) func() {
	t.Helper()
	paths := []string{filepath.Join(observerMediaRoot, "history-full-witness.bin")}
	cleanup := func() {
		for _, path := range paths {
			if os.Remove(path) != nil {
				t.Error("history filler cleanup")
			}
		}
	}
	f, err := os.OpenFile(paths[0], os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal("history filler create", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = f.Close()
		}
	}()
	buf := make([]byte, 4096)
	full := false
	for count := 0; count < 32<<20; {
		n, err := f.Write(buf)
		count += n
		if errors.Is(err, unix.ENOSPC) {
			full = true
			break
		}
		if err != nil || n != len(buf) {
			t.Fatal("history filler unexpected write", err)
		}
	}
	if !full {
		t.Fatal("history filler did not observe ENOSPC")
	}
	if err := f.Sync(); err != nil && !errors.Is(err, unix.ENOSPC) {
		t.Fatal("history filler sync", err)
	}
	if f.Close() != nil {
		t.Fatal("history filler close")
	}
	closed = true
	var fs unix.Statfs_t
	for i := 0; i < 16; i++ {
		if unix.Statfs(observerMediaRoot, &fs) != nil {
			t.Fatal("history filler statfs")
		}
		if fs.Bavail == 0 {
			break
		}
		path := filepath.Join(observerMediaRoot, fmt.Sprintf("history-tail-%02d.bin", i))
		tail, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal("history tail create", err)
		}
		paths = append(paths, path)
		n, writeErr := tail.Write([]byte{1})
		syncErr := tail.Sync()
		closeErr := tail.Close()
		if n != 1 || writeErr != nil || syncErr != nil || closeErr != nil {
			t.Fatal("history tail allocation")
		}
	}
	if unix.Statfs(observerMediaRoot, &fs) != nil || fs.Bavail != 0 {
		t.Fatal("history actual full medium not established")
	}
	return func() {
		cleanup()
		if unix.Statfs(observerMediaRoot, &fs) != nil || fs.Bavail == 0 {
			t.Error("history available space not restored")
		}
	}
}
