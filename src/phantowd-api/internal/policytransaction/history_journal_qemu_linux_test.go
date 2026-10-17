//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

func journalFixture(t *testing.T) (*historyJournal, string) {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil || os.Mkdir(filepath.Join(root, "operations"), 0700) != nil {
		t.Fatal("layout")
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := parent.Close(); err != nil {
			t.Error(err)
		}
	})
	j, err := newHistoryJournal(parent)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := j.close(); err != nil {
			t.Error(err)
		}
	})
	return j, root
}

func TestHistoryJournalRetainsTwoIndependentConfirmedRecords(t *testing.T) {
	j, root := journalFixture(t)
	anchor, current, records, _ := bundleHistoryFixture(t)
	for _, record := range records {
		confirmed, err := decodeBundle(bytes.NewReader(record.Data))
		if err != nil {
			t.Fatal(err)
		}
		defer confirmed.clear()
		intent := bundle{installation: confirmed.installation, revision: 1, base: bytes.Clone(confirmed.base), intent: bytes.Clone(confirmed.intent)}
		defer intent.clear()
		name := bundleHistoryName(t, record.Data)
		if err := j.begin(name, intent); err != nil {
			t.Fatal("intent", err)
		}
		if err := j.confirm(name, confirmed); err != nil {
			t.Fatal("confirmation", err)
		}
		data, err := os.ReadFile(filepath.Join(root, "operations", name))
		if err != nil || !bytes.Equal(data, record.Data) {
			t.Fatal("historical record changed", err)
		}
	}
	entries, err := j.observe()
	if err != nil {
		t.Fatal(err)
	}
	d, err := MatchNamedBundleHistoryObservation(testInstallation, anchor, current, entries)
	if err != nil || d.Kind() != policyevidence.LocalConfirmationObserved {
		t.Fatal(d, err)
	}
	probe, err := os.Open(filepath.Join(root, "operations"))
	if err != nil {
		t.Fatal(err)
	}
	defer probe.Close()
	if err := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB); !errors.Is(err, unix.EWOULDBLOCK) {
		t.Fatal("journal lock gap", err)
	}
}

func TestHistoryJournalRefusesWriteOpenEvenWithUnchangedConfirmedBytes(t *testing.T) {
	j, root := journalFixture(t)
	_, _, records, _ := bundleHistoryFixture(t)
	b, err := decodeBundle(bytes.NewReader(records[0].Data))
	if err != nil {
		t.Fatal(err)
	}
	defer b.clear()
	i := bundle{installation: b.installation, revision: 1, base: bytes.Clone(b.base), intent: bytes.Clone(b.intent)}
	defer i.clear()
	name := bundleHistoryName(t, records[0].Data)
	if j.begin(name, i) != nil || j.confirm(name, b) != nil {
		t.Fatal("publication")
	}
	f, err := os.OpenFile(filepath.Join(root, "operations", name), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if f.Close() != nil {
		t.Fatal("fixture close")
	}
	for range 2 {
		if entries, err := j.observe(); entries != nil || !errors.Is(err, ErrReview) {
			t.Fatal("restored write-open adopted", err)
		}
	}
}

func TestHistoryJournalRetainsLatePendingWithoutAnyRecovery(t *testing.T) {
	j, root := journalFixture(t)
	path := filepath.Join(root, "operations", journalPending)
	if os.WriteFile(path, []byte("uncertain private staged bytes"), 0600) != nil {
		t.Fatal("pending")
	}
	if _, err := j.observe(); !errors.Is(err, ErrReview) {
		t.Fatal("pending admitted", err)
	}
	if os.Remove(path) != nil {
		t.Fatal("fixture restoration")
	}
	if _, err := j.observe(); !errors.Is(err, ErrReview) {
		t.Fatal("restoration resumed lifetime", err)
	}
}

func TestHistoryJournalWatchEnrollmentFailureStillClosesOriginalsOnce(t *testing.T) {
	j, _ := journalFixture(t)
	_, _, records, _ := bundleHistoryFixture(t)
	b, err := decodeBundle(bytes.NewReader(records[0].Data))
	if err != nil {
		t.Fatal(err)
	}
	defer b.clear()
	i := bundle{installation: b.installation, revision: 1, base: bytes.Clone(b.base), intent: bytes.Clone(b.intent)}
	defer i.clear()
	name := bundleHistoryName(t, records[0].Data)
	if j.begin(name, i) != nil {
		t.Fatal("intent")
	}
	j.watchFile = func(*os.File) error { return errors.New("private controlled watch enrollment failure") }
	if err := j.confirm(name, b); !errors.Is(err, ErrReview) {
		t.Fatal("failed watch admitted", err)
	}
	if err := j.close(); err != nil {
		t.Fatal("completed close retried or original lost", err)
	}
}

func TestHistoryJournalCapacityRefusalDoesNotPruneOrPoison(t *testing.T) {
	j, _ := journalFixture(t)
	for range policyevidence.MaxHistoryOperations {
		b, _, _ := fixture(t)
		defer b.clear()
		i, err := policyevidence.DecodeIntent(bytes.NewReader(b.intent))
		if err != nil {
			t.Fatal(err)
		}
		name, err := i.OperationRecordName()
		if err != nil {
			t.Fatal(err)
		}
		confirmed, err := confirmedBundle(b)
		if err != nil {
			t.Fatal(err)
		}
		defer confirmed.clear()
		if j.begin(name, b) != nil || j.confirm(name, confirmed) != nil {
			t.Fatal("bounded record publication")
		}
	}
	b, _, _ := fixture(t)
	defer b.clear()
	i, _ := policyevidence.DecodeIntent(bytes.NewReader(b.intent))
	name, _ := i.OperationRecordName()
	if err := j.begin(name, b); err != ErrInvalid {
		t.Fatal("one beyond admitted", err)
	}
	entries, err := j.observe()
	if err != nil || j.review || len(entries) != policyevidence.MaxHistoryOperations {
		t.Fatal("capacity refusal deleted or poisoned evidence", err)
	}
}
