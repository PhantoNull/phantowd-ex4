//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicyevidence"
	"golang.org/x/sys/unix"
)

func requireNASEvidenceReview(t *testing.T, a *NASEvidenceAuthority, dir string) {
	t.Helper()
	for range 2 {
		if got, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) || got != (NASEvidenceObservation{}) {
			t.Fatal("review returned usable or partial observation", got, err)
		}
	}
	if other, err := OpenNASEvidenceAuthority(context.Background(), dir, evidenceInstallation); !errors.Is(err, ErrBusy) {
		if other != nil {
			other.Close()
		}
		t.Fatal("review released original lock", err)
	}
}

func TestNASEvidenceContainerMetadataHeadersAndOrphans(t *testing.T) {
	for _, name := range []string{
		"wide-mode", "symlink", "hardlink", "directory", "fifo", "future-header",
		"extra-header-key", "duplicate-header-key", "seven-roles", "changed-base-bytes",
		"receipt-orphan", "base-orphan",
	} {
		t.Run(name, func(t *testing.T) {
			dir, ctx := nasEvidenceFixture(t), context.Background()
			leaf := filepath.Join(dir, ".nas-services.base")
			check := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			write := func(role string, b []byte) {
				t.Helper()
				check(os.WriteFile(filepath.Join(dir, role), b, 0600))
			}
			header := func() string {
				t.Helper()
				b, err := os.ReadFile(filepath.Join(dir, "nas-evidence.json"))
				check(err)
				return string(b)
			}
			want := naspolicyevidence.Unavailable
			switch name {
			case "wide-mode":
				check(os.Chmod(leaf, 0644))
			case "symlink":
				check(os.Remove(leaf))
				check(os.Symlink(filepath.Join(t.TempDir(), "missing"), leaf))
			case "hardlink":
				check(os.Link(leaf, filepath.Join(t.TempDir(), "alias")))
			case "directory", "fifo":
				check(os.Remove(leaf))
				if name == "fifo" {
					check(unix.Mkfifo(leaf, 0600))
				} else {
					check(os.Mkdir(leaf, 0600))
				}
			case "future-header":
				write("nas-evidence.json", []byte(strings.Replace(header(), `"schema_version":1`, `"schema_version":2`, 1)))
			case "extra-header-key":
				write("nas-evidence.json", []byte(strings.TrimSuffix(header(), "}")+`,"other":1}`))
			case "duplicate-header-key":
				write("nas-evidence.json", []byte(strings.TrimSuffix(header(), "}")+`,"schema_version":1}`))
			case "seven-roles":
				write(".nas-services.pending", []byte("metadata-only"))
				write("extra", []byte("preserve"))
			case "changed-base-bytes":
				b, err := os.ReadFile(leaf)
				check(err)
				write(".nas-services.base", append(b, '\n'))
				want = naspolicyevidence.Inconsistent
			case "receipt-orphan", "base-orphan":
				check(os.Remove(filepath.Join(dir, ".nas-services.intent")))
				if name == "base-orphan" {
					check(os.Remove(filepath.Join(dir, ".nas-services.receipt")))
				}
				want = naspolicyevidence.Inconsistent
			}
			a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
			check(err)
			defer a.Close()
			got, err := a.Observe(ctx)
			if want == naspolicyevidence.Unavailable {
				if !errors.Is(err, ErrReview) || got != (NASEvidenceObservation{}) {
					t.Fatal("unsafe evidence not refused completely", got, err)
				}
			} else if err != nil || got.Kind != want {
				t.Fatal("orphan or changed base appeared coherent", got, err)
			}
			requireNASEvidenceReview(t, a, dir)
		})
	}
}

func TestNASEvidenceContainerAbsenceAndReadOnlyPreservation(t *testing.T) {
	for _, noOperation := range []bool{false, true} {
		t.Run(map[bool]string{false: "absent-base", true: "no-operation"}[noOperation], func(t *testing.T) {
			dir, ctx := nasEvidenceFixture(t), context.Background()
			names, want := []string{".nas-services.base"}, naspolicyevidence.MatchingLocalRecords
			if noOperation {
				names = append(names, ".nas-services.intent", ".nas-services.receipt")
				want = naspolicyevidence.NoRecordedOperation
			}
			for _, name := range names {
				if err := os.Remove(filepath.Join(dir, name)); err != nil {
					t.Fatal(err)
				}
			}
			before := map[string]string{}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if err != nil {
					t.Fatal(err)
				}
				before[entry.Name()] = string(b)
			}
			a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
			if err != nil {
				t.Fatal(err)
			}
			defer a.Close()
			for range 3 {
				got, err := a.Observe(ctx)
				if err != nil || got.Kind != want || got.BasePresent || got.Pending || got.Roles != len(before) {
					t.Fatal("absence fabricated or pristine assumed", got, err)
				}
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadDir(dir)
			if err != nil || len(after) != len(before) {
				t.Fatal("observation created or removed evidence", err)
			}
			for _, entry := range after {
				b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
				if original, ok := before[entry.Name()]; err != nil || !ok || original != string(b) {
					t.Fatal("observation altered evidence", err)
				}
			}
		})
	}
}

func TestNASEvidenceContainerWritableOpenAndPreworkCancellation(t *testing.T) {
	dir, ctx := nasEvidenceFixture(t), context.Background()
	a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got, err := a.Observe(canceled); !errors.Is(err, context.Canceled) || got != (NASEvidenceObservation{}) {
		t.Fatal("prework cancellation returned evidence", got, err)
	}
	if _, err := a.Observe(ctx); err != nil {
		t.Fatal("prework cancellation poisoned original lifetime", err)
	}
	if _, err := json.Marshal(a); !errors.Is(err, ErrInvalid) {
		t.Fatal("authority serialized", err)
	}
	if err := json.Unmarshal([]byte("{}"), a); !errors.Is(err, ErrInvalid) {
		t.Fatal("authority deserialized", err)
	}
	file, err := os.OpenFile(filepath.Join(dir, "nas-services.json"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	requireNASEvidenceReview(t, a, dir)
}

// Controlled context fault: calibrate the actual read's cancellation polls,
// then cancel at each poll after prework. No timer, scheduler race or new hook.
type nasEvidenceCancelPoll struct {
	context.Context
	cancel    context.CancelFunc
	calls, at int
}

func (c *nasEvidenceCancelPoll) Err() error {
	c.calls++
	if c.at > 0 && c.calls == c.at {
		c.cancel()
	}
	return c.Context.Err()
}

func TestNASEvidenceContainerInFlightCancellationRetainsOriginalLock(t *testing.T) {
	dir := nasEvidenceFixture(t)
	a, err := OpenNASEvidenceAuthority(context.Background(), dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	probe := &nasEvidenceCancelPoll{Context: context.Background()}
	if _, err := a.Observe(probe); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if probe.calls < 4 {
		t.Fatal("fixture did not reach evidence reading")
	}
	for at := 3; at <= probe.calls; at++ {
		a, err := OpenNASEvidenceAuthority(context.Background(), dir, evidenceInstallation)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { a.Close() })
		ctx, cancel := context.WithCancel(context.Background())
		fault := &nasEvidenceCancelPoll{Context: ctx, cancel: cancel, at: at}
		got, err := a.Observe(fault)
		cancel()
		if !errors.Is(err, context.Canceled) || !errors.Is(err, ErrReview) || got != (NASEvidenceObservation{}) {
			t.Fatal("in-flight cancellation published evidence", at, got, err)
		}
		requireNASEvidenceReview(t, a, dir)
		if err := a.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func TestNASEvidenceContainerRepeatedReadsDoNotAccumulateDescriptors(t *testing.T) {
	dir, ctx := nasEvidenceFixture(t), context.Background()
	a, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	if _, err := a.Observe(ctx); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		t.Fatal(err)
	}
	for range 32 {
		if got, err := a.Observe(ctx); err != nil || got.Kind != naspolicyevidence.MatchingLocalRecords {
			t.Fatal("repeated original observation unavailable", got, err)
		}
	}
	after, err := os.ReadDir("/proc/self/fd")
	if err != nil || len(after) != len(before) {
		t.Fatal("repeated observations accumulated descriptors", len(before), len(after), err)
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); err != nil {
		t.Fatal("verified closure was not idempotent", err)
	}
	other, err := OpenNASEvidenceAuthority(ctx, dir, evidenceInstallation)
	if err != nil {
		t.Fatal("verified close retained observer-only lock", err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestNASEvidenceContainerUncertainCloseNeverRetriesOriginalDescriptor(t *testing.T) {
	dir := nasEvidenceFixture(t)
	a, err := OpenNASEvidenceAuthority(context.Background(), dir, evidenceInstallation)
	if err != nil {
		t.Fatal(err)
	}
	// Test-only premature watch close, not real media EIO. Open no new file
	// before first Close so the raw descriptor cannot be recycled by the probe.
	if err := unix.Close(a.root.watch); err != nil {
		t.Fatal(err)
	}
	if err := a.Close(); !errors.Is(err, ErrReview) {
		t.Fatal("uncertain close reported success", err)
	}
	defer a.root.root.Close() // Explicit disposal of the independent fixture.
	for range 3 {
		if err := a.Close(); !errors.Is(err, ErrReview) {
			t.Fatal("uncertain close was retried", err)
		}
		requireNASEvidenceReview(t, a, dir)
	}
}
