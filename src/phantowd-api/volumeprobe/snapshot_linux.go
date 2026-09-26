// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package volumeprobe

import (
	"context"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

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
	if ctx == nil || sources == nil || len(sources) > MaxSources {
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
		file *os.File
		stat unix.Stat_t
		kind string
	}
	inputs := make([]pinned, 0, len(sources))
	defer func() {
		for _, input := range inputs {
			input.file.Close()
		}
	}()
	for _, source := range sources {
		if err := ctx.Err(); err != nil {
			return Snapshot{}, err
		}
		file, stat, kind, err := retain(source)
		if err != nil {
			return Snapshot{}, err
		}
		inputs = append(inputs, pinned{file, stat, kind})
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
		if unix.Fstat(int(input.file.Fd()), &after) != nil || !sameObject(input.stat, after) {
			return Snapshot{}, ErrUnsafe
		}
	}
	if err := ctx.Err(); err != nil {
		return Snapshot{}, err
	}
	return makeSnapshot(entries)
}
