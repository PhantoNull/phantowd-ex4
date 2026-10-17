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
)

func TestHistoryJournalSecondIntentPartialWriteRetainsFirstRecord(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil || os.Mkdir(filepath.Join(root, "operations"), 0700) != nil {
		t.Fatal("layout")
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	fired := 0
	j, err := newHistoryJournalWithCrash(parent, &disposableCrash{role: "intent", point: "partial-write", gate: func() { fired++ }})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if j.close() != nil {
			t.Error("close")
		}
	}()
	_, _, records, unconfirmed := bundleHistoryFixture(t)
	first, err := decodeBundle(bytes.NewReader(records[0].Data))
	if err != nil {
		t.Fatal(err)
	}
	defer first.clear()
	i := bundle{installation: first.installation, revision: 1, base: bytes.Clone(first.base), intent: bytes.Clone(first.intent)}
	defer i.clear()
	name := bundleHistoryName(t, records[0].Data)
	if j.begin(name, i) != nil || j.confirm(name, first) != nil || fired != 0 {
		t.Fatal("first operation affected")
	}
	before := j.records[name]
	second, err := decodeBundle(bytes.NewReader(unconfirmed))
	if err != nil {
		t.Fatal(err)
	}
	defer second.clear()
	nextIntent, err := policyevidence.DecodeIntent(bytes.NewReader(second.intent))
	if err != nil {
		t.Fatal(err)
	}
	secondName, err := nextIntent.OperationRecordName()
	if err != nil {
		t.Fatal(err)
	}
	if err := j.begin(secondName, second); !errors.Is(err, ErrReview) || fired != 1 {
		t.Fatal("returning gate admitted", err)
	}
	data, err := os.ReadFile(filepath.Join(root, "operations", journalPending))
	if err != nil || !bytes.Equal(data, []byte(`{"format`)) {
		t.Fatal("not an actual eight-byte write", err)
	}
	if j.records[name].file != before.file || j.records[name].stamp != before.stamp || !bytes.Equal(j.records[name].wire, before.wire) {
		t.Fatal("first original changed")
	}
	for range 2 {
		if j.begin(secondName, second) != ErrReview || fired != 1 {
			t.Fatal("uncertain operation retried")
		}
	}
}

func TestHistoryJournalReturningCrashBoundariesPreserveFirstAndFence(t *testing.T) {
	for _, role := range []string{"intent", "receipt"} {
		for _, point := range syscallCrashPoints {
			t.Run(role+"/"+point, func(t *testing.T) {
				root := t.TempDir()
				if os.Chmod(root, 0700) != nil || os.Mkdir(filepath.Join(root, "operations"), 0700) != nil {
					t.Fatal("layout")
				}
				parent, err := os.Open(root)
				if err != nil {
					t.Fatal(err)
				}
				defer parent.Close()
				fired := 0
				plan := &disposableCrash{role: role, point: point, gate: func() { fired++ }}
				j, err := newHistoryJournalWithCrash(parent, plan)
				if err != nil {
					t.Fatal(err)
				}
				defer func() {
					if j.close() != nil {
						t.Error("close")
					}
				}()
				plan.role, plan.point, plan.gate = "unknown", "unknown", nil // captured copy, never adopted
				_, _, records, unconfirmed := bundleHistoryFixture(t)
				first, _ := decodeBundle(bytes.NewReader(records[0].Data))
				defer first.clear()
				i := bundle{installation: first.installation, revision: 1, base: bytes.Clone(first.base), intent: bytes.Clone(first.intent)}
				defer i.clear()
				name := bundleHistoryName(t, records[0].Data)
				if j.begin(name, i) != nil || j.confirm(name, first) != nil || fired != 0 {
					t.Fatal("first operation intercepted")
				}
				original := j.records[name]
				second, _ := decodeBundle(bytes.NewReader(unconfirmed))
				defer second.clear()
				confirmed, _ := decodeBundle(bytes.NewReader(records[1].Data))
				defer confirmed.clear()
				secondName := bundleHistoryName(t, records[1].Data)
				err = j.begin(secondName, second)
				if role == "receipt" {
					if err != nil || fired != 0 {
						t.Fatal("receipt plan intercepted intent")
					}
					err = j.confirm(secondName, confirmed)
				}
				if !errors.Is(err, ErrReview) || fired != 1 {
					t.Fatal("returning crash gate admitted", err)
				}
				data := make([]byte, len(original.wire))
				n, err := original.file.ReadAt(data, 0)
				meta, metaErr := journalStat(original.file)
				if n != len(data) || err != nil || metaErr != nil || meta != original.stamp || !bytes.Equal(data, original.wire) {
					t.Fatal("first original changed")
				}
				published := point == "after-rename" || point == "directory-sync"
				pending, pendingErr := os.ReadFile(filepath.Join(root, "operations", journalPending))
				if published {
					if !os.IsNotExist(pendingErr) {
						t.Fatal("published pending survived")
					}
				} else if pendingErr != nil || point == "partial-write" && !bytes.Equal(pending, []byte(`{"format`)) {
					t.Fatal("wrong pending boundary", pendingErr)
				}
				for range 2 {
					if j.begin(secondName, second) != ErrReview || fired != 1 {
						t.Fatal("new operation/retry admitted")
					}
				}
			})
		}
	}
}

func TestHistoryCrashPlansRefuseBeforeAnyNamespace(t *testing.T) {
	for _, plan := range []*disposableCrash{{role: "other", point: "file-sync", gate: func() {}}, {role: "intent", point: "other", gate: func() {}}, {role: "receipt", point: "file-sync"}} {
		if owned, err := copyHistoryCrash(plan, true); owned != nil || err != ErrInvalid {
			t.Fatal("invalid profile copied")
		}
		if j, err := newHistoryJournalWithCrash(nil, plan); j != nil || err != ErrInvalid {
			t.Fatal("invalid child profile reached filesystem")
		}
	}
}
