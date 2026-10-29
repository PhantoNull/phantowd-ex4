//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
)

func nasWriterPolicy(t *testing.T, revision uint64) []byte {
	t.Helper()
	c := nasKillPolicy(2) // Preserve the retained export's volume/path binding.
	c.Revision, c.FileServices.Revision, c.FileServices.Shares.Revision = revision, revision, revision
	c.FileServices.NFS.Revision, c.FileServices.NFS.VolumeRevision = revision, revision
	c.ISCSI.Revision, c.ISCSI.VolumeRevision = revision, revision
	b, err := json.Marshal(c)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestNASWriterRotatesTwoConfirmedOperationsUnderOneLock(t *testing.T) {
	dir, ctx := nasEvidenceFixture(t), context.Background()
	base := nasWriterPolicy(t, 2)
	w, err := openNASWriter(ctx, dir, evidenceInstallation, base, systemNASWriterBackend())
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	var previous string
	for _, revision := range []uint64{3, 4} {
		next := nasWriterPolicy(t, revision)
		if err := w.Commit(ctx, nasWriterPolicy(t, 1), next); !errors.Is(err, ErrConflict) {
			t.Fatal("stale base accepted", err)
		}
		if err := w.Commit(ctx, base, next); err != nil {
			t.Fatal("ordered commit failed", revision, err)
		}
		for role, want := range map[string][]byte{"nas-services.json": next, ".nas-services.base": base} {
			got, err := os.ReadFile(filepath.Join(dir, role))
			if err != nil || !bytes.Equal(got, want) {
				t.Fatal("exact current/base evidence differs", role, err)
			}
		}
		intent, err := os.ReadFile(filepath.Join(dir, ".nas-services.intent"))
		if err != nil {
			t.Fatal(err)
		}
		receipt, err := os.ReadFile(filepath.Join(dir, ".nas-services.receipt"))
		if err != nil || naspolicyevidence.Inspect(evidenceInstallation, next, intent, receipt, true) != naspolicyevidence.MatchingLocalRecords {
			t.Fatal("operation evidence does not match", err)
		}
		var record struct {
			Operation string `json:"operation_id"`
		}
		if json.Unmarshal(intent, &record) != nil || record.Operation == previous {
			t.Fatal("operation ID reused")
		}
		previous, base = record.Operation, next
		if other, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
			if other != nil {
				other.Close()
			}
			t.Fatal("original lock not retained", err)
		}
	}
}

func TestNASWriterUncertainStagesKeepReviewAndOriginalLock(t *testing.T) {
	for target := 1; target <= 4; target++ {
		points := strings.Fields("write short sync close before-rename rename dir-sync readback cancel-write cancel-sync cancel-close cancel-rename cancel-dir-sync")
		if target == 2 {
			points = append(points, strings.Fields("before-retire retire retire-sync cancel-before-retire cancel-retire cancel-retire-sync")...)
		}
		for _, point := range points {
			t.Run(strconv.Itoa(target)+"/"+point, func(t *testing.T) {
				dir := nasEvidenceFixture(t)
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				backend, stage, calls, fired, retiring := systemNASWriterBackend(), 0, 0, false, false
				real := backend.io
				fault := func(phase string) error {
					calls++
					if stage == target && (point == phase || point == "cancel-"+phase) {
						fired = true
						if strings.HasPrefix(point, "cancel-") {
							cancel()
							return nil
						}
						return ErrIO
					}
					return nil
				}
				backend.io.write = func(f *os.File, b []byte) (int, error) {
					stage++
					if stage == target && point == "short" {
						fired = true
						return real.write(f, b[:1])
					}
					n, err := real.write(f, b)
					return n, errors.Join(err, fault("write"))
				}
				backend.io.sync = func(f *os.File) error { return errors.Join(real.sync(f), fault("sync")) }
				backend.io.close = func(f *os.File) error { return errors.Join(real.close(f), fault("close")) }
				backend.io.rename = func(a int, b string, c int, d string) error {
					if err := fault("before-rename"); err != nil {
						return err
					}
					return errors.Join(real.rename(a, b, c, d), fault("rename"))
				}
				backend.remove = func(fd int, name string, flags int) error {
					if err := fault("before-retire"); err != nil {
						return err
					}
					retiring = true
					return errors.Join(systemNASWriterBackend().remove(fd, name, flags), fault("retire"))
				}
				backend.io.syncDir = func(fd int) error {
					phase := "dir-sync"
					if retiring {
						phase, retiring = "retire-sync", false
					}
					if stage == target && point == "readback" && phase == "dir-sync" {
						fired = true
						return errors.Join(real.syncDir(fd), os.WriteFile(filepath.Join(dir, []string{".nas-services.base", ".nas-services.intent", "nas-services.json", ".nas-services.receipt"}[stage-1]), []byte("controlled drift"), 0600))
					}
					return errors.Join(real.syncDir(fd), fault(phase))
				}
				base, next := nasWriterPolicy(t, 2), nasWriterPolicy(t, 3)
				w, err := openNASWriter(ctx, dir, evidenceInstallation, base, backend)
				if err != nil {
					t.Fatal(err)
				}
				defer w.Close()
				if err := w.Commit(ctx, base, next); !errors.Is(err, ErrReview) || !fired {
					t.Fatal("fault was not quarantined", err, fired)
				}
				before := calls
				if err := w.Commit(context.Background(), base, next); !errors.Is(err, ErrReview) || calls != before {
					t.Fatal("review retried effects", err)
				}
				if other, err := OpenNASEvidenceAuthority(context.Background(), dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
					if other != nil {
						other.Close()
					}
					t.Fatal("uncertainty released original authority", err)
				}
			})
		}
	}
}

func TestNASWriterPreservesDriftObservedBeforeFirstStage(t *testing.T) {
	dir, ctx := nasEvidenceFixture(t), context.Background()
	base, evidence := nasWriterPolicy(t, 2), []byte("unexpected base evidence")
	backend := systemNASWriterBackend()
	backend.random = func(b []byte) (int, error) {
		for i := range b {
			b[i] = 0x33
		}
		return len(b), os.WriteFile(filepath.Join(dir, ".nas-services.base"), evidence, 0600)
	}
	w, err := openNASWriter(ctx, dir, evidenceInstallation, base, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer w.Close()
	if err := w.Commit(ctx, base, nasWriterPolicy(t, 3)); !errors.Is(err, ErrReview) {
		t.Fatal("pre-stage drift did not quarantine", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".nas-services.base"))
	if err != nil || !bytes.Equal(got, evidence) {
		t.Fatal("unknown base evidence overwritten", err)
	}
	if _, err := os.Lstat(filepath.Join(dir, ".nas-services.pending")); !os.IsNotExist(err) {
		t.Fatal("pre-stage refusal created pending", err)
	}
}
