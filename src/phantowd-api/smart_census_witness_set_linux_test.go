// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartdevice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func emptySMARTWitnessFS() fstest.MapFS {
	return fstest.MapFS{"class": {Mode: fs.ModeDir | 0555}, "class/block": {Mode: fs.ModeDir | 0555}}
}

type lateFailureSMARTWitnessFS struct {
	fs.FS
	reads, failAt int
}

func (f *lateFailureSMARTWitnessFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "class/block" {
		f.reads++
		if f.reads == f.failAt {
			return nil, fs.ErrInvalid
		}
	}
	return fs.ReadDir(f.FS, name)
}

func TestSMARTCensusWitnessSetFinalCensusFailureStaysReview(t *testing.T) {
	reader := &lateFailureSMARTWitnessFS{FS: emptySMARTWitnessFS()}
	s, err := retainSMARTCensusWitnessSet(context.Background(), reader, []volumeprobe.BlockDeviceSource{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(context.Background())
	// Each complete empty census has initial and final directory reads. Fail
	// only the final census after the first sample and witness phase succeed.
	reader.failAt = reader.reads + 3
	if !errors.Is(s.Check(context.Background()), smartdevice.ErrUnsafe) || reader.reads != reader.failAt {
		t.Fatal("late full-inventory failure was accepted or not exercised")
	}
	reader.failAt = 0
	if !errors.Is(s.Check(context.Background()), smartdevice.ErrReview) {
		t.Fatal("late uncertainty resumed after reader restoration")
	}
}

func TestSMARTCensusWitnessSetEmptyLifecycleAndStickyReview(t *testing.T) {
	sysfs := emptySMARTWitnessFS()
	s, err := retainSMARTCensusWitnessSet(context.Background(), sysfs, []volumeprobe.BlockDeviceSource{})
	if err != nil || s == nil || s.Check(context.Background()) != nil {
		t.Fatal("complete empty observation refused", err)
	}
	defer s.Close(context.Background())
	directory := sysfs["class/block"]
	sysfs["class/block"] = &fstest.MapFile{Data: []byte("not a directory")}
	if !errors.Is(s.Check(context.Background()), smartdevice.ErrUnsafe) {
		t.Fatal("incomplete full census accepted")
	}
	sysfs["class/block"] = directory
	if !errors.Is(s.Check(context.Background()), smartdevice.ErrReview) {
		t.Fatal("restored inventory resumed quarantined witnesses")
	}
	if s.Close(context.Background()) != nil || s.Close(context.Background()) != nil ||
		!errors.Is(s.Check(context.Background()), smartdevice.ErrClosed) {
		t.Fatal("explicit empty-set release incorrect")
	}
}

func TestSMARTCensusWitnessSetRefusesCopiesBusyInvalidAndCanceled(t *testing.T) {
	ctx := context.Background()
	s, err := retainSMARTCensusWitnessSet(ctx, emptySMARTWitnessFS(), []volumeprobe.BlockDeviceSource{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close(ctx)
	copy := *s
	if !errors.Is(copy.Check(ctx), smartdevice.ErrUnsafe) || !errors.Is(copy.Close(ctx), smartdevice.ErrUnsafe) {
		t.Fatal("copy forked witness ownership")
	}
	s.gate <- struct{}{}
	if !errors.Is(s.Check(ctx), smartdevice.ErrBusy) || !errors.Is(s.Close(ctx), smartdevice.ErrBusy) {
		t.Fatal("concurrent operation was admitted")
	}
	<-s.gate
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if !errors.Is(s.Check(canceled), context.Canceled) || !errors.Is(s.Close(canceled), context.Canceled) || s.Check(ctx) != nil {
		t.Fatal("pre-operation cancellation changed ownership")
	}
	for _, invalid := range []*smartCensusWitnessSet{nil, {}} {
		if !errors.Is(invalid.Check(ctx), smartdevice.ErrUnsafe) || !errors.Is(invalid.Close(ctx), smartdevice.ErrUnsafe) {
			t.Fatal("unconstructed ownership admitted")
		}
	}
	if !errors.Is(s.Check(nil), smartdevice.ErrUnsafe) || !errors.Is(s.Close(nil), smartdevice.ErrUnsafe) {
		t.Fatal("nil context admitted")
	}
	for _, value := range []any{s, *s} {
		if _, err := json.Marshal(value); !errors.Is(err, errSMARTCensusPrivate) {
			t.Fatal("private ownership serialized", err)
		}
	}
	if !errors.Is(json.Unmarshal([]byte("{}"), s), errSMARTCensusPrivate) || s.Check(ctx) != nil {
		t.Fatal("JSON replaced trusted state")
	}
}

func TestSMARTCensusWitnessSetRequiresCompleteUniqueSourcesAndBorrowsFiles(t *testing.T) {
	sysfs := fixtureDiscoverySysfs()
	census, err := collectSMARTDiskCensus(context.Background(), sysfs)
	if err != nil {
		t.Fatal(err)
	}
	sources := make([]volumeprobe.BlockDeviceSource, len(census.disks))
	for i, disk := range census.disks {
		path := filepath.Join(t.TempDir(), strconv.Itoa(i))
		if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
			t.Fatal(err)
		}
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		sources[i] = volumeprobe.BlockDeviceSource{File: file, Generation: disk.generation}
	}
	duplicates := append([]volumeprobe.BlockDeviceSource{}, sources...)
	duplicates[1] = duplicates[0]
	for _, candidate := range [][]volumeprobe.BlockDeviceSource{nil, {}, sources[:1], duplicates, sources} {
		if s, err := retainSMARTCensusWitnessSet(context.Background(), sysfs, candidate); s != nil || !errors.Is(err, smartdevice.ErrUnsafe) {
			t.Fatal("partial, duplicate or non-block input accepted", err)
		}
		for _, source := range sources {
			if _, err := source.File.Stat(); err != nil {
				t.Fatal("borrowed source was closed", err)
			}
		}
	}
	for _, test := range []struct {
		ctx   context.Context
		sysfs fs.FS
	}{
		{nil, sysfs}, {context.Background(), nil}, {context.Background(), fstest.MapFS{}},
	} {
		if s, err := retainSMARTCensusWitnessSet(test.ctx, test.sysfs, sources); s != nil || !errors.Is(err, smartdevice.ErrUnsafe) {
			t.Fatal("invalid observation admitted", err)
		}
	}
	if s, err := retainSMARTCensusWitnessSet(context.Background(), emptySMARTWitnessFS(), nil); s != nil || !errors.Is(err, smartdevice.ErrUnsafe) {
		t.Fatal("nil source set treated as observed empty")
	}
}

func TestSMARTCensusWitnessSetUncertainReleaseCannotBecomeSuccess(t *testing.T) {
	s, err := retainSMARTCensusWitnessSet(context.Background(), emptySMARTWitnessFS(), []volumeprobe.BlockDeviceSource{})
	if err != nil {
		t.Fatal(err)
	}
	// Synthetic invalid owner, not an actual kernel close-error reproduction.
	s.witnesses = []*smartdevice.Witness{nil}
	if !errors.Is(s.Close(context.Background()), smartdevice.ErrReview) ||
		!errors.Is(s.Close(context.Background()), smartdevice.ErrReview) ||
		!errors.Is(s.Check(context.Background()), smartdevice.ErrReview) || s.closed {
		t.Fatal("uncertain release became successful")
	}
}
