// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeregistry

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"
)

func TestRegistryRecheckStableAndBoundToReader(t *testing.T) {
	_, borrowed := readerFixture(t)
	r, err := Open(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := r.Read(context.Background())
	if err != nil || r.Recheck(context.Background(), s) != nil {
		t.Fatal("stable protected observation refused", err)
	}
	other, err := Open(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if other.Recheck(context.Background(), s) != ErrObservation {
		t.Fatal("snapshot crossed Reader provenance")
	}
	if _, err := json.Marshal(s); err == nil {
		t.Fatal("provenance escaped JSON")
	}
	if err := borrowed.Close(); err != nil || r.Recheck(context.Background(), s) != nil {
		t.Fatal("borrowed close invalidated owned reader", err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Recheck(context.Background(), s); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if err := r.Close(); err != nil || r.Recheck(context.Background(), s) != ErrObservation {
		t.Fatal("closed Reader accepted", err)
	}
	if _, err := s.Claims(); err != nil {
		t.Fatal("snapshot lost point-in-time claims", err)
	}
}

func TestRegistryRecheckRejectsInvalidPriorBeforeIO(t *testing.T) {
	dir, borrowed := readerFixture(t)
	r, err := Open(borrowed)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	s, err := r.Read(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, test := range []struct {
		name     string
		ctx      context.Context
		previous Snapshot
	}{
		{"zero", context.Background(), Snapshot{}},
		{"origin missing", context.Background(), Snapshot{observed: true, document: fixtureDocument()}},
		{"nil context", nil, s}, {"canceled", ctx, s},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			if r.recheck(test.ctx, test.previous, func() { calls++ }) != ErrObservation || calls != 0 {
				t.Fatal("invalid prior reached protected read")
			}
		})
	}
	// Forged metadata-valid provenance does not make invalid claims valid.
	invalid := s
	invalid.document = Document{}
	if r.recheck(context.Background(), invalid, func() { t.Fatal("invalid claims reached read") }) != ErrObservation {
		t.Fatal("invalid claims accepted")
	}
	var nilReader *Reader
	if nilReader.Recheck(context.Background(), s) != ErrObservation {
		t.Fatal("nil reader accepted")
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	freshDir, err := os.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer freshDir.Close()
	reopened, err := Open(freshDir)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if reopened.recheck(context.Background(), s, func() { t.Fatal("reopened prior reached read") }) != ErrObservation {
		t.Fatal("reopened reader rehabilitated prior")
	}
}

func TestRegistryRecheckDetectsEqualRevisionAndRestoredBytes(t *testing.T) {
	for _, kind := range []string{"same bytes replace", "rewrite", "same revision claims", "mode restore", "directory ABA", "missing", "unsafe mode", "directory mode"} {
		t.Run(kind, func(t *testing.T) {
			dir, borrowed := readerFixture(t)
			r, err := Open(borrowed)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			prior, err := r.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			file := filepath.Join(dir, currentName)
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch kind {
			case "same bytes replace":
				must(os.Rename(file, filepath.Join(dir, "old")))
				must(os.WriteFile(file, data, 0600))
			case "rewrite":
				must(os.WriteFile(file, []byte("{}"), 0600))
				must(os.WriteFile(file, data, 0600))
			case "same revision claims":
				d := fixtureDocument()
				d.Volumes[0].ID = "different-books"
				changed, err := json.Marshal(d)
				must(err)
				must(os.WriteFile(file, changed, 0600))
			case "mode restore":
				must(os.Chmod(file, 0644))
				must(os.Chmod(file, 0600))
			case "directory ABA":
				temporary := filepath.Join(dir, "unrelated")
				must(os.WriteFile(temporary, []byte("fixture"), 0600))
				must(os.Remove(temporary))
			case "missing":
				must(os.Remove(file))
			case "unsafe mode":
				must(os.Chmod(file, 0644))
			case "directory mode":
				must(os.Chmod(dir, 0755))
			}
			if r.Recheck(context.Background(), prior) != ErrObservation {
				t.Fatal("changed observation accepted", kind)
			}
			if kind == "missing" || kind == "unsafe mode" || kind == "directory mode" {
				return
			}
			// A fresh explicit observation is allowed; old input is not rehabilitated.
			fresh, err := r.Read(context.Background())
			if err != nil || r.Recheck(context.Background(), fresh) != nil {
				t.Fatal("fresh explicit observation refused", err)
			}
			if r.Recheck(context.Background(), prior) != ErrObservation {
				t.Fatal("fresh read cleared prior drift")
			}
			if kind != "same revision claims" {
				a, _ := prior.Claims()
				b, _ := fresh.Claims()
				if !reflect.DeepEqual(a, b) {
					t.Fatal("restored claims fixture changed semantics")
				}
			}
		})
	}
}

func TestRegistryRecheckRefusesChangesDuringProtectedReread(t *testing.T) {
	for _, kind := range []string{"replacement", "directory entry", "cancel"} {
		t.Run(kind, func(t *testing.T) {
			dir, borrowed := readerFixture(t)
			r, err := Open(borrowed)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			prior, err := r.Read(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			err = r.recheck(ctx, prior, func() {
				var err error
				switch kind {
				case "replacement":
					file := filepath.Join(dir, currentName)
					data, e := os.ReadFile(file)
					if e != nil {
						t.Fatal(e)
					}
					err = os.Rename(file, filepath.Join(dir, "old"))
					if err == nil {
						err = os.WriteFile(file, data, 0600)
					}
				case "directory entry":
					err = os.WriteFile(filepath.Join(dir, "extra"), []byte("fixture"), 0600)
				case "cancel":
					cancel()
				}
				if err != nil {
					t.Fatal(err)
				}
			})
			if err != ErrObservation {
				t.Fatal("race accepted", err)
			}
		})
	}
}
