// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestObserveSetAliasesAndClones(t *testing.T) {
	a, helper := fixture(t, successScript())
	b, _ := fixture(t, successScript())
	aliasName := filepath.Join(filepath.Dir(a.Name()), "alias")
	if err := os.Link(a.Name(), aliasName); err != nil {
		t.Fatal(err)
	}
	alias, err := os.Open(aliasName)
	if err != nil {
		t.Fatal(err)
	}
	defer alias.Close()
	for _, test := range []struct {
		sources []*os.File
		state   string
	}{
		{[]*os.File{a, alias}, "one-object"},
		{[]*os.File{a, b, alias}, "conflicting-objects"},
		{[]*os.File{b, alias, a}, "conflicting-objects"},
	} {
		snapshot, err := observeSet(context.Background(), test.sources, helper, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		match, err := snapshot.MatchUUID("00112233-4455-6677-8899-aabbccddeeff")
		if err != nil || match.State != test.state || len(match.SourceIndices) != len(test.sources) {
			t.Fatal(match, err)
		}
		for _, file := range test.sources {
			if _, err := file.Stat(); err != nil {
				t.Fatal("closed caller input")
			}
		}
	}
}

func TestObserveSetNoPartialResults(t *testing.T) {
	a, helper := fixture(t, successScript())
	for _, sources := range [][]*os.File{nil, {a, nil}, make([]*os.File, MaxSources+1)} {
		snapshot, err := observeSet(context.Background(), sources, helper, time.Second)
		if !errors.Is(err, ErrUnsafe) || len(snapshot.Results()) != 0 {
			t.Fatal(snapshot, err)
		}
	}
	if snapshot, err := ObserveSet(context.Background(), []*os.File{}); err != nil || len(snapshot.Results()) != 0 {
		t.Fatal("explicit empty set", err)
	}
	if _, err := ObserveSet(nil, []*os.File{}); !errors.Is(err, ErrUnsafe) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := ObserveSet(ctx, []*os.File{a}); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if _, err := observeSet(context.Background(), []*os.File{a}, "/nonexistent/helper", time.Second); !errors.Is(err, ErrProbe) {
		t.Fatal(err)
	}
	active.Store(true)
	_, err := ObserveSet(context.Background(), []*os.File{a})
	active.Store(false)
	if !errors.Is(err, ErrBusy) {
		t.Fatal(err)
	}
}

func TestObserveSetRechecksEarlierFiles(t *testing.T) {
	a, helper := fixture(t, successScript())
	b, _ := fixture(t, successScript())
	marker := filepath.Join(filepath.Dir(helper), "second")
	// The second child changes the first regular image after it was probed.
	// Per-child checks alone would miss this and return an inconsistent set.
	script := "#!/bin/sh\nif test -e '" + marker + "'; then printf changed >> '" + a.Name() + "'; else touch '" + marker + "'; fi\n" + successScript() + "\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	snapshot, err := observeSet(context.Background(), []*os.File{a, b}, helper, time.Second)
	if !errors.Is(err, ErrUnsafe) || len(snapshot.Results()) != 0 {
		t.Fatal("partial/mutated snapshot", err)
	}
}

func TestObserveSetDeadline(t *testing.T) {
	a, helper := fixture(t, "exec sleep 10")
	snapshot, err := observeSet(context.Background(), []*os.File{a, a}, helper, 80*time.Millisecond)
	if !errors.Is(err, context.DeadlineExceeded) || len(snapshot.Results()) != 0 {
		t.Fatal(snapshot, err)
	}
}

func TestObserveSetDiscardsEarlierSuccess(t *testing.T) {
	a, helper := fixture(t, successScript())
	b, _ := fixture(t, successScript())
	marker := filepath.Join(filepath.Dir(helper), "seen")
	script := "#!/bin/sh\nif test -e '" + marker + "'; then exit 1; fi\ntouch '" + marker + "'\n" + successScript() + "\n"
	if err := os.WriteFile(helper, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	snapshot, err := observeSet(context.Background(), []*os.File{a, b}, helper, time.Second)
	if !errors.Is(err, ErrProbe) || len(snapshot.Results()) != 0 {
		t.Fatal("earlier result escaped failed set", err)
	}
	if _, err := ObserveSet(context.Background(), []*os.File{}); err != nil {
		t.Fatal("failed set retained slot", err)
	}
}
