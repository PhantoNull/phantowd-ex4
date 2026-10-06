//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smartdevice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/volumeprobe"
	"golang.org/x/sys/unix"
)

// A fixed reader with test-only injected read failure, not a sysfs mutation,
// hardware hotplug simulation, replacement backend or product provider.
type qemuSMARTWitnessSetFS struct {
	base fs.FS
	fail bool
}

var _ fs.ReadLinkFS = (*qemuSMARTWitnessSetFS)(nil)

func (f *qemuSMARTWitnessSetFS) Open(name string) (fs.File, error) {
	if f.fail {
		return nil, fs.ErrInvalid
	}
	return f.base.Open(name)
}

func (f *qemuSMARTWitnessSetFS) ReadLink(name string) (string, error) {
	if f.fail {
		return "", fs.ErrInvalid
	}
	return fs.ReadLink(f.base, name)
}

func (f *qemuSMARTWitnessSetFS) Lstat(name string) (fs.FileInfo, error) {
	if f.fail {
		return nil, fs.ErrInvalid
	}
	return fs.Lstat(f.base, name)
}

// Called only inside the existing exact-machine, root, active-MD fixture.
// Every source is an already-attached disposable virtual disk; only O_RDONLY
// opens and metadata ioctls occur. No content or SMART transport is inspected.
func exerciseQEMUSMARTCensusWitnessSet() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	reader := &qemuSMARTWitnessSetFS{base: os.DirFS("/sys")}
	census, err := collectSMARTDiskCensus(ctx, reader)
	if err != nil || len(census.disks) != 7 {
		return errors.New("SMART set fixture census incomplete")
	}
	devices := make([]volumeprobe.ObservedBlockDevice, len(census.disks))
	for i, disk := range census.disks {
		devices[i] = volumeprobe.ObservedBlockDevice{Name: disk.name, Generation: disk.generation}
	}
	initialFDs, err := qemuSMARTSourceFDCount(devices)
	if err != nil {
		return err
	}
	sources, err := volumeprobe.OpenObservedBlockSources(devices)
	if err != nil {
		return errors.New("SMART set fixed read-only fixture opener refused")
	}
	defer func() {
		for _, source := range sources {
			source.File.Close()
		}
	}()
	if s, err := retainSMARTCensusWitnessSet(ctx, reader, sources[:len(sources)-1]); s != nil || !errors.Is(err, smartdevice.ErrUnsafe) {
		if s != nil {
			s.Close(context.Background())
		}
		return errors.New("SMART set accepted missing leaf")
	}
	invalid, err := os.Open("/dev/null")
	if err != nil {
		return err
	}
	defer invalid.Close()
	bad := append([]volumeprobe.BlockDeviceSource{}, sources...)
	bad[len(bad)-1].File = invalid
	if s, err := retainSMARTCensusWitnessSet(ctx, reader, bad); s != nil || !errors.Is(err, smartdevice.ErrUnsafe) {
		if s != nil {
			s.Close(context.Background())
		}
		return errors.New("SMART set accepted non-block final source")
	}
	if count, err := qemuSMARTSourceFDCount(devices); err != nil || count != initialFDs+len(sources) {
		return errors.New("SMART set partial-retain rollback leaked block descriptors")
	}
	// Input order does not select a device: the complete generation matcher
	// determines pairing. No name/index becomes stable media identity.
	reversed := append([]volumeprobe.BlockDeviceSource{}, sources...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	s, err := retainSMARTCensusWitnessSet(ctx, reader, reversed)
	if err != nil {
		return errors.New("SMART complete set retain failed")
	}
	defer s.Close(context.Background())
	for _, source := range sources {
		if source.File.Close() != nil {
			return errors.New("SMART set caller close uncertain")
		}
		if _, err := source.File.Stat(); !errors.Is(err, os.ErrClosed) {
			return errors.New("SMART set caller descriptor remains open")
		}
	}
	if s.Check(ctx) != nil {
		return errors.New("SMART set did not retain caller-independent complete pins")
	}
	reader.fail = true
	if !errors.Is(s.Check(ctx), smartdevice.ErrUnsafe) {
		return errors.New("SMART set accepted failed full-census read")
	}
	reader.fail = false
	if !errors.Is(s.Check(ctx), smartdevice.ErrReview) {
		return errors.New("SMART set resumed after reader restoration")
	}
	if count, err := qemuSMARTSourceFDCount(devices); err != nil || count != initialFDs+len(sources) {
		return errors.New("SMART set did not retain all review pins")
	}
	if s.Close(ctx) != nil || !errors.Is(s.Check(ctx), smartdevice.ErrClosed) {
		return errors.New("SMART set explicit release failed")
	}
	if count, err := qemuSMARTSourceFDCount(devices); err != nil || count != initialFDs {
		return errors.New("SMART set explicit release leaked block descriptors")
	}
	return nil
}

// Bound this test-only census to current-process FDs and known fixture device
// numbers; report only a count. No link targets, unrelated IDs or paths escape.
func qemuSMARTSourceFDCount(devices []volumeprobe.ObservedBlockDevice) (int, error) {
	directory, err := os.Open("/proc/self/fd")
	if err != nil {
		return 0, errors.New("SMART fixture descriptor census unavailable")
	}
	names, readErr := directory.Readdirnames(129)
	closeErr := directory.Close()
	if (readErr != nil && !errors.Is(readErr, io.EOF)) || closeErr != nil || len(names) > 128 {
		return 0, errors.New("SMART fixture descriptor census incomplete")
	}
	count := 0
	for _, name := range names {
		fd, err := strconv.Atoi(name)
		if err != nil || fd < 0 {
			return 0, errors.New("SMART fixture descriptor identity invalid")
		}
		var st unix.Stat_t
		if err := unix.Fstat(fd, &st); errors.Is(err, unix.EBADF) {
			continue
		} else if err != nil {
			return 0, errors.New("SMART fixture descriptor observation failed")
		}
		if st.Mode&unix.S_IFMT != unix.S_IFBLK {
			continue
		}
		for _, device := range devices {
			if unix.Major(uint64(st.Rdev)) == device.Generation.Major && unix.Minor(uint64(st.Rdev)) == device.Generation.Minor {
				count++
				break
			}
		}
	}
	return count, nil
}
