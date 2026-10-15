// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartdevice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
)

func TestSMARTCensusOpenEmptyFixedLifecycle(t *testing.T) {
	// A complete EMPTY inventory opens no /dev path and grants no media access.
	s, err := openSMARTCensusWitnessSet(context.Background(), emptySMARTWitnessFS())
	if err != nil || s == nil || len(s.witnesses) != 0 || s.openedSources != nil || s.Check(context.Background()) != nil {
		t.Fatal("observed-empty fixed constructor failed", err)
	}
	if s.Close(context.Background()) != nil || !errors.Is(s.Check(context.Background()), smartdevice.ErrClosed) {
		t.Fatal("empty opener lifecycle did not close")
	}
}

func TestSMARTCensusOpenRefusesBeforeCallingOpener(t *testing.T) {
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		ctx   context.Context
		sysfs fs.FS
	}{
		{nil, emptySMARTWitnessFS()}, {context.Background(), nil},
		{context.Background(), fstest.MapFS{}}, {canceled, fixtureDiscoverySysfs()},
	} {
		calls := 0
		s, err := openSMARTCensusWitnessSetWith(tc.ctx, tc.sysfs, func([]volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
			calls++
			return nil, nil
		})
		if s != nil || err == nil || calls != 0 {
			t.Fatal("invalid/incomplete/canceled constructor opened devices", err, calls)
		}
	}
	if s, err := openSMARTCensusWitnessSetWith(context.Background(), emptySMARTWitnessFS(), nil); s != nil || !errors.Is(err, smartdevice.ErrUnsafe) {
		t.Fatal("missing fixed opener accepted")
	}
}

func TestSMARTCensusOpenDerivesCompleteNamesIncludingInUseAndAmbiguous(t *testing.T) {
	sysfs := fixtureDiscoverySysfs()
	census, err := collectSMARTDiskCensus(context.Background(), sysfs)
	if err != nil {
		t.Fatal(err)
	}
	want := make([]volumeprobe.ObservedBlockDevice, len(census.disks))
	for i, disk := range census.disks {
		want[i] = volumeprobe.ObservedBlockDevice{Name: disk.name, Generation: disk.generation}
	}
	private := errors.New("private-path-and-device-identity")
	calls := 0
	s, err := openSMARTCensusWitnessSetWith(context.Background(), sysfs, func(got []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		calls++
		if !reflect.DeepEqual(got, want) || len(got) != 5 {
			t.Fatal("opener omitted/replaced a whole leaf", got)
		}
		return nil, private
	})
	if s != nil || !errors.Is(err, smartdevice.ErrUnsafe) || calls != 1 || strings.Contains(err.Error(), "private") {
		t.Fatal("untrusted opener error or partial result escaped", err)
	}
}

func TestSMARTCensusOpenRejectsNilMissingDuplicateAndNonBlockSourcesAndClosesOwnedFiles(t *testing.T) {
	for _, kind := range []string{"nil", "missing", "duplicate", "non-block", "partial-error", "canceled"} {
		t.Run(kind, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			var owned []*os.File
			s, err := openSMARTCensusWitnessSetWith(ctx, fixtureDiscoverySysfs(), func(devices []volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
				if kind == "nil" {
					return nil, nil
				}
				var sources []volumeprobe.BlockDeviceSource
				for _, device := range devices {
					file, err := os.CreateTemp(t.TempDir(), "source-")
					if err != nil {
						t.Fatal(err)
					}
					// Deliberately regular/non-block: this may NEVER simulate a healthy disk.
					owned = append(owned, file)
					sources = append(sources, volumeprobe.BlockDeviceSource{File: file, Generation: device.Generation})
					if kind == "missing" || kind == "partial-error" {
						break
					}
				}
				if kind == "duplicate" {
					sources = append(sources, sources[0])
				}
				if kind == "partial-error" {
					return sources, errors.New("private-opener-failure")
				}
				if kind == "canceled" {
					cancel()
				}
				return sources, nil
			})
			if s != nil || err == nil || strings.Contains(err.Error(), "private") {
				t.Fatal("invalid owned set admitted", err)
			}
			if kind == "canceled" && !errors.Is(err, context.Canceled) {
				t.Fatal("opener cancellation lost", err)
			}
			for _, file := range owned {
				if _, err := file.Stat(); !errors.Is(err, os.ErrClosed) {
					t.Fatal("constructor leaked opened source", err)
				}
			}
		})
	}
}

func TestSMARTCensusOpenDoesNotAdoptAReplacementCensus(t *testing.T) {
	sysfs := emptySMARTWitnessFS()
	s, err := openSMARTCensusWitnessSetWith(context.Background(), sysfs, func([]volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		// Mutate only fake sysfs AFTER initial census; the new inventory must
		// not silently become the constructor's trusted baseline.
		for name, entry := range fixtureDiscoverySysfs() {
			sysfs[name] = entry
		}
		return []volumeprobe.BlockDeviceSource{}, nil
	})
	if s != nil || !errors.Is(err, smartdevice.ErrUnsafe) {
		t.Fatal("post-open replacement census admitted", err)
	}
}

func TestSMARTCensusOpenUncertainSourceCloseRetainsReviewWithoutRetry(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "already-closed-")
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := openSMARTCensusWitnessSetWith(context.Background(), emptySMARTWitnessFS(), func([]volumeprobe.ObservedBlockDevice) ([]volumeprobe.BlockDeviceSource, error) {
		return []volumeprobe.BlockDeviceSource{{File: file}}, errors.New("private-opener-failure")
	})
	// Synthetic repeated-close refusal, not a kernel block-close fault claim.
	if s == nil || !errors.Is(err, smartdevice.ErrReview) || !s.releaseUncertain || len(s.openedSources) != 1 {
		t.Fatal("uncertain source release lost review authority", err)
	}
	if !errors.Is(s.Check(context.Background()), smartdevice.ErrReview) || !errors.Is(s.Close(context.Background()), smartdevice.ErrReview) || s.closed {
		t.Fatal("uncertain constructor cleanup was retried as success")
	}
}
