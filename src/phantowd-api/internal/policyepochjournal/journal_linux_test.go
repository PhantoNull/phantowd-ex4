//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyepochjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

func journalFixture(t *testing.T) (*Journal, *os.File, string) {
	t.Helper()
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil || os.Mkdir(filepath.Join(root, "policy-session"), 0700) != nil {
		t.Fatal("fixture layout")
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	j, err := OpenFresh(context.Background(), parent, testInstallation, math.MaxUint64)
	if err != nil {
		parent.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if j.Close() != nil {
			t.Error("journal close")
		}
		if parent.Close() != nil {
			t.Error("parent close")
		}
	})
	return j, parent, root
}

func TestJournalRecordsOneOpeningAndClosure(t *testing.T) {
	j, _, root := journalFixture(t)
	ctx := context.Background()
	base, next := policyAt(t, 1), policyAt(t, 2)
	d, err := j.Observe(ctx, base)
	if err != nil || d.Kind() != policyevidence.NoEpochRecorded {
		t.Fatal("empty declaration observation")
	}
	if err := j.RecordOpening(ctx, base); err != nil {
		t.Fatal(err)
	}
	d, err = j.Observe(ctx, base)
	if err != nil || d.Kind() != policyevidence.OpenEpochObserved {
		t.Fatal("opening observation")
	}
	if err := j.RecordClosure(ctx, next); err != nil {
		t.Fatal(err)
	}
	d, err = j.Observe(ctx, next)
	if err != nil || d.Kind() != policyevidence.ClosureMatchesCurrent {
		t.Fatal("closure observation")
	}
	if err := j.RecordOpening(ctx, next); err != ErrConflict {
		t.Fatal("opening repeated")
	}
	if err := j.RecordClosure(ctx, next); err != ErrConflict {
		t.Fatal("closure repeated")
	}
	info, err := os.Stat(filepath.Join(root, "policy-session/epoch.json"))
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("record mode")
	}
	if _, err := json.Marshal(j); !errors.Is(err, ErrPrivate) {
		t.Fatal("journal JSON admitted")
	}
}

func TestJournalValueCopiesStayPrivate(t *testing.T) {
	j, _, _ := journalFixture(t)
	// Reflection boxes a value copy without calling pointer-only methods. The
	// copy is never used to operate its old lock or close original references.
	value := reflect.ValueOf(j).Elem().Interface()
	for _, v := range []any{j, value} {
		if strings.Contains(fmt.Sprintf("%#v", v), testInstallation) {
			t.Fatal("journal value formatting disclosed identity")
		}
		if _, err := json.Marshal(v); !errors.Is(err, ErrPrivate) {
			t.Fatal("journal value JSON admitted")
		}
	}
	copy := value.(Journal)
	if copy.RecordOpening(context.Background(), policyAt(t, 1)) != ErrInvalid || copy.Close() != ErrInvalid {
		t.Fatal("copy operated original lifetime")
	}
	if _, err := copy.Observe(context.Background(), policyAt(t, 1)); err != ErrInvalid {
		t.Fatal("copy observed original lifetime")
	}
}

func TestJournalConcurrentFormattingDoesNotReadMutableState(t *testing.T) {
	j, _, _ := journalFixture(t)
	var wg sync.WaitGroup
	failed := make(chan bool, 1)
	wg.Add(1)
	defer wg.Wait()
	go func() {
		defer wg.Done()
		for range 1000 {
			if strings.Contains(fmt.Sprintf("%#v", j), testInstallation) {
				failed <- true
				return
			}
			if _, err := json.Marshal(j); !errors.Is(err, ErrPrivate) {
				failed <- true
				return
			}
		}
	}()
	if err := j.RecordOpening(context.Background(), policyAt(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordClosure(context.Background(), policyAt(t, 2)); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	if len(failed) != 0 {
		t.Fatal("concurrent private formatting failed")
	}
}

func TestJournalExclusiveFreshOnlyAndCloseDoesNotDeclareClosure(t *testing.T) {
	j, parent, root := journalFixture(t)
	ctx := context.Background()
	if other, err := OpenFresh(ctx, parent, testInstallation, 1); err != ErrBusy || other != nil {
		t.Fatal("actual child lock not retained")
	}
	if err := j.RecordOpening(ctx, policyAt(t, 1)); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "policy-session/epoch.json")
	before, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.Close(); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("Close modified evidence")
	}
	d, err := decodeDocument(bytes.NewReader(after))
	if err != nil || d.Revision != 1 || d.Closure != "" {
		t.Fatal("Close manufactured closure")
	}
	if other, err := OpenFresh(ctx, parent, testInstallation, 1); err != ErrExisting || other != nil {
		t.Fatal("existing evidence adopted")
	}
	again, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(before, again) {
		t.Fatal("failed fresh opener changed evidence")
	}
}

func TestJournalBeforeEffectRefusalsAndConcurrency(t *testing.T) {
	j, _, root := journalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	base := policyAt(t, 1)
	if err := j.RecordOpening(ctx, base); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-cancel not refused")
	}
	if err := j.RecordClosure(context.Background(), base); err != ErrConflict {
		t.Fatal("closure without opening")
	}
	if err := j.RecordOpening(context.Background(), []byte(`{}`)); err != ErrInvalid {
		t.Fatal("invalid policy admitted")
	}
	entries, err := os.ReadDir(filepath.Join(root, "policy-session"))
	if err != nil || len(entries) != 0 || j.state.review {
		t.Fatal("pre-effect refusal mutated role")
	}
	var results [2]error
	var wg sync.WaitGroup
	wg.Add(2)
	for i := range 2 {
		go func(i int) { defer wg.Done(); results[i] = j.RecordOpening(context.Background(), base) }(i)
	}
	wg.Wait()
	won, conflict := 0, 0
	for _, err := range results {
		if err == nil {
			won++
		} else if err == ErrConflict {
			conflict++
		} else {
			t.Fatal(err)
		}
	}
	if won != 1 || conflict != 1 {
		t.Fatal("not exactly one opening")
	}
	if err := j.RecordClosure(context.Background(), append(bytes.Clone(base), '\n')); err != ErrInvalid || j.state.review {
		t.Fatal("same-revision mismatch not refused before effects")
	}
}

func TestJournalUncertainPublicationRetainsReview(t *testing.T) {
	for _, closure := range []bool{false, true} {
		for _, after := range []bool{false, true} {
			for _, cancelled := range []bool{false, true} {
				t.Run(fmt.Sprintf("closure=%v/after=%v/cancel=%v", closure, after, cancelled), func(t *testing.T) {
					j, _, root := journalFixture(t)
					base, next := policyAt(t, 1), policyAt(t, 2)
					if closure {
						if err := j.RecordOpening(context.Background(), base); err != nil {
							t.Fatal(err)
						}
					}
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					actual := j.state.commit
					calls := 0
					j.state.commit = func(expected uint64, d document) error {
						calls++
						if after {
							if err := actual(expected, d); err != nil {
								return err
							}
						}
						if cancelled {
							cancel()
							return nil
						}
						return errors.New("private controlled publication failure")
					}
					var err error
					if closure {
						err = j.RecordClosure(ctx, next)
					} else {
						err = j.RecordOpening(ctx, base)
					}
					if !errors.Is(err, ErrReview) || calls != 1 || !j.state.review {
						t.Fatal("uncertainty not fenced")
					}
					if cancelled && !errors.Is(err, context.Canceled) {
						t.Fatal("cancellation classification lost")
					}
					file := filepath.Join(root, "policy-session/epoch.json")
					before, readErr := os.ReadFile(file)
					for range 2 {
						if err := j.RecordOpening(context.Background(), base); err != ErrReview {
							t.Fatal("opening retry admitted")
						}
						if err := j.RecordClosure(context.Background(), next); err != ErrReview {
							t.Fatal("closure retry admitted")
						}
						if _, err := j.Observe(context.Background(), next); err != ErrReview {
							t.Fatal("observation after review")
						}
						afterBytes, afterErr := os.ReadFile(file)
						if (readErr == nil) != (afterErr == nil) || !bytes.Equal(before, afterBytes) || calls != 1 {
							t.Fatal("reviewed evidence changed")
						}
					}
				})
			}
		}
	}
}

func TestJournalLatePendingIsPreservedAfterRestoration(t *testing.T) {
	j, _, root := journalFixture(t)
	pending := filepath.Join(root, "policy-session/.epoch.pending")
	const evidence = "private incomplete evidence"
	if os.WriteFile(pending, []byte(evidence), 0600) != nil {
		t.Fatal("pending fixture")
	}
	if err := j.RecordOpening(context.Background(), policyAt(t, 1)); !errors.Is(err, ErrReview) {
		t.Fatal("late pending accepted")
	}
	wire, err := os.ReadFile(pending)
	if err != nil || string(wire) != evidence {
		t.Fatal("pending altered")
	}
	if os.Remove(pending) != nil {
		t.Fatal("fixture restoration")
	}
	if err := j.RecordOpening(context.Background(), policyAt(t, 1)); err != ErrReview {
		t.Fatal("restoration revived journal")
	}
}

func TestFreshConstructorPreservesUnknownOrPendingEvidence(t *testing.T) {
	for _, name := range []string{".epoch.pending", "unknown", "epoch.json"} {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil || os.Mkdir(filepath.Join(root, "policy-session"), 0700) != nil {
				t.Fatal("layout")
			}
			file := filepath.Join(root, "policy-session", name)
			const evidence = "private existing evidence"
			if os.WriteFile(file, []byte(evidence), 0600) != nil {
				t.Fatal("existing fixture")
			}
			parent, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			if j, err := OpenFresh(context.Background(), parent, testInstallation, 1); j != nil || err != ErrReview {
				t.Fatal("existing/unknown/pending admitted")
			}
			wire, err := os.ReadFile(file)
			if err != nil || string(wire) != evidence {
				t.Fatal("constructor changed evidence")
			}
		})
	}
}

func TestFreshConstructorNeverCreatesMissingRole(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("root mode")
	}
	parent, err := os.Open(root)
	if err != nil {
		t.Fatal(err)
	}
	defer parent.Close()
	if j, err := OpenFresh(context.Background(), parent, testInstallation, 1); j != nil || err != ErrReview {
		t.Fatal("missing role admitted")
	}
	if _, err := os.Stat(filepath.Join(root, "policy-session")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("constructor created role")
	}
}

func TestJournalCloseUncertaintyNeverRetriesOrWrites(t *testing.T) {
	for _, after := range []bool{false, true} {
		t.Run(fmt.Sprint(after), func(t *testing.T) {
			root := t.TempDir()
			if os.Chmod(root, 0700) != nil || os.Mkdir(filepath.Join(root, "policy-session"), 0700) != nil {
				t.Fatal("layout")
			}
			parent, err := os.Open(root)
			if err != nil {
				t.Fatal(err)
			}
			defer parent.Close()
			j, err := OpenFresh(context.Background(), parent, testInstallation, 1)
			if err != nil {
				t.Fatal(err)
			}
			actual := j.state.closeStore
			attempted := false
			defer func() {
				if !attempted {
					attempted = true
					if actual() != nil {
						t.Error("known fixture settlement")
					}
				}
			}()
			if err := j.RecordOpening(context.Background(), policyAt(t, 1)); err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(root, "policy-session/epoch.json")
			before, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			calls := 0
			j.state.closeStore = func() error {
				calls++
				if after {
					attempted = true
					if err := actual(); err != nil {
						return err
					}
				}
				return errors.New("private controlled close failure")
			}
			for range 2 {
				if err := j.Close(); err != ErrReview {
					t.Fatal("uncertain Close accepted")
				}
			}
			if calls != 1 || !j.state.closeFailed || j.state.closed {
				t.Fatal("Close retried or misclassified")
			}
			if err := j.RecordClosure(context.Background(), policyAt(t, 2)); err != ErrReview {
				t.Fatal("closed failure revived")
			}
			wire, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(before, wire) {
				t.Fatal("Close changed evidence")
			}
		})
	}
}
