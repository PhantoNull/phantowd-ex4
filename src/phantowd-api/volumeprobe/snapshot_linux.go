// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"context"
	"os"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// OpenObservedBlockSources opens exactly the already-observed whole-disk
// candidates beneath the fixed /dev directory. It accepts no caller path,
// uses read-only descriptors, and returns no partial set. The caller must
// still establish complete discovery, eligibility, unmounted state and stable
// topology, then reconcile the sysfs inventory before any handoff or action.
func OpenObservedBlockSources(devices []ObservedBlockDevice) ([]BlockDeviceSource, error) {
	if err := validateObservedBlockDevices(devices); err != nil {
		return nil, err
	}
	if len(devices) == 0 {
		return []BlockDeviceSource{}, nil
	}
	devRootFD, err := unix.Openat2(unix.AT_FDCWD, "/dev", &unix.OpenHow{
		Flags:   unix.O_PATH | unix.O_DIRECTORY | unix.O_CLOEXEC,
		Resolve: unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
	})
	if err != nil {
		return nil, ErrUnsafe
	}
	defer unix.Close(devRootFD)
	return openObservedBlockSourcesAt(devRootFD, devices)
}

func openObservedBlockSourcesAt(devRootFD int, devices []ObservedBlockDevice) (sources []BlockDeviceSource, err error) {
	if devRootFD < 0 || validateObservedBlockDevices(devices) != nil {
		return nil, ErrUnsafe
	}
	if len(devices) == 0 {
		return []BlockDeviceSource{}, nil
	}
	sources = make([]BlockDeviceSource, 0, len(devices))
	opened := make([]*os.File, 0, len(devices))
	defer func() {
		if err != nil {
			for _, file := range opened {
				file.Close()
			}
			sources = nil
		}
	}()
	for _, device := range devices {
		fd, openErr := unix.Openat2(devRootFD, device.Name, &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_NONBLOCK | unix.O_CLOEXEC | unix.O_NOCTTY,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS,
		})
		if openErr != nil {
			return nil, ErrUnsafe
		}
		file := os.NewFile(uintptr(fd), "observed-block-source")
		if file == nil {
			unix.Close(fd)
			return nil, ErrUnsafe
		}
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || !matchesBlockGeneration(file, stat, "block-device", device.Generation) {
			file.Close()
			return nil, ErrUnsafe
		}
		source := BlockDeviceSource{File: file, Generation: device.Generation}
		sources = append(sources, source)
		opened = append(opened, file)
	}
	for _, source := range sources {
		var stat unix.Stat_t
		if unix.Fstat(int(source.File.Fd()), &stat) != nil ||
			!matchesBlockGeneration(source.File, stat, "block-device", source.Generation) {
			return nil, ErrUnsafe
		}
	}
	return sources, nil
}

// ObserveSet retains all supplied descriptors, probes sequentially under one
// process-wide slot, then rechecks every object before returning any result.
// The 30-second set deadline bounds interruptible work, not kernel D-state I/O.
// The caller must establish eligibility/exclusivity and stable topology; this
// function does not enumerate/open device paths or establish unmounted state.
// Source ownership and shared-offset rules are the same as Inspect.
func ObserveSet(ctx context.Context, sources []*os.File) (Snapshot, error) {
	return observeSet(ctx, sources, "/usr/libexec/phantowd-volume-probe", 30*time.Second)
}

func observeSet(ctx context.Context, sources []*os.File, executable string, timeout time.Duration) (Snapshot, error) {
	return observeDescriptors(ctx, sources, nil, executable, timeout)
}

// ObserveBlockSet accepts only block descriptors matching their caller-observed
// major/minor and disk sequence both before probing and before returning. The
// caller must prequalify these as whole-disk sources (not partitions), establish
// discovery completeness, eligibility, stable topology and unmounted state.
// This does not enumerate paths, establish media identity, or authorize
// mounting. A held descriptor's unchanged generation does not prove its
// pathname still names that object; the caller must reconcile the final
// inventory before handoff.
// It has the same timeout, single-slot, source-ownership and shared-offset
// requirements as ObserveSet.
func ObserveBlockSet(ctx context.Context, sources []BlockDeviceSource) (Snapshot, error) {
	return observeBlockSet(ctx, sources, "/usr/libexec/phantowd-volume-probe", 30*time.Second)
}

func observeBlockSet(ctx context.Context, sources []BlockDeviceSource, executable string, timeout time.Duration) (Snapshot, error) {
	if sources == nil || len(sources) > MaxSources {
		return Snapshot{}, ErrUnsafe
	}
	files := make([]*os.File, len(sources))
	generations := make([]BlockDeviceGeneration, len(sources))
	for i, source := range sources {
		files[i], generations[i] = source.File, source.Generation
	}
	return observeDescriptors(ctx, files, generations, executable, timeout)
}

// A nil generations slice keeps ObserveSet's regular-image behavior. A
// non-nil slice requires every retained descriptor to match one generation.
func observeDescriptors(ctx context.Context, sources []*os.File, generations []BlockDeviceGeneration, executable string, timeout time.Duration) (Snapshot, error) {
	if ctx == nil || sources == nil || len(sources) > MaxSources {
		return Snapshot{}, ErrUnsafe
	}
	if generations != nil && (len(generations) != len(sources) || !validGenerationSet(generations)) {
		return Snapshot{}, ErrUnsafe
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	if !active.CompareAndSwap(false, true) {
		return Snapshot{}, ErrBusy
	}
	defer active.Store(false)
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	type pinned struct {
		file       *os.File
		stat       unix.Stat_t
		kind       string
		generation BlockDeviceGeneration
		bound      bool
	}
	inputs := make([]pinned, 0, len(sources))
	defer func() {
		for _, input := range inputs {
			input.file.Close()
		}
	}()
	for i, source := range sources {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		file, stat, kind, err := retain(source)
		if err != nil {
			return Snapshot{}, err
		}
		input := pinned{file: file, stat: stat, kind: kind}
		if generations != nil {
			input.generation = generations[i]
			input.bound = true
		}
		inputs = append(inputs, input)
		if input.bound && !matchesBlockGeneration(file, stat, kind, input.generation) {
			return Snapshot{}, ErrUnsafe
		}
	}
	entries := make([]observation, 0, len(inputs))
	for _, input := range inputs {
		result, err := inspectPinned(ctx, input.file, input.stat, input.kind, executable, 8*time.Second)
		if err != nil {
			return Snapshot{}, err
		}
		key := objectKey{kind: input.kind}
		if input.kind == "block-device" {
			key.rawDevice = uint64(input.stat.Rdev)
		} else {
			key.device, key.inode = uint64(input.stat.Dev), uint64(input.stat.Ino)
		}
		entries = append(entries, observation{result, key})
	}
	// A mutation of an earlier object during a later probe invalidates the set.
	for _, input := range inputs {
		var after unix.Stat_t
		if unix.Fstat(int(input.file.Fd()), &after) != nil || !sameObject(input.stat, after) ||
			(input.bound && !matchesBlockGeneration(input.file, after, input.kind, input.generation)) {
			return Snapshot{}, ErrUnsafe
		}
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return makeSnapshot(entries)
}

func matchesBlockGeneration(file *os.File, stat unix.Stat_t, kind string, expected BlockDeviceGeneration) bool {
	if kind != "block-device" ||
		uint32(unix.Major(uint64(stat.Rdev))) != expected.Major ||
		uint32(unix.Minor(uint64(stat.Rdev))) != expected.Minor {
		return false
	}
	sequence, err := readDiskSequence(int(file.Fd()))
	return err == nil && sequence != 0 && sequence == expected.DiskSequence
}

func readDiskSequence(fd int) (uint64, error) {
	var sequence uint64
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(unix.BLKGETDISKSEQ), uintptr(unsafe.Pointer(&sequence)))
	runtime.KeepAlive(&sequence)
	if errno != 0 {
		return 0, errno
	}
	return sequence, nil
}
