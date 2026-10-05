//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package backingpin

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// Pinned Linux 6.18 configfs default names plus explicit owned policy objects.
// This is bounded point-in-time observation, not exclusive writer authority.
const lioRosterLimit = 64

type lioDirectoryRoster struct {
	directory *os.File // borrowed from the backend's owned entry ledger
	names     []string // privately generated; never read from an observed baseline
}

func lioExactNames(expected, observed []string) bool {
	if len(expected) > lioRosterLimit || len(observed) != len(expected) {
		return false
	}
	names := make(map[string]bool, len(expected))
	valid := func(name string) bool {
		return name != "" && name != "." && name != ".." && len(name) <= 255 && !strings.ContainsAny(name, "/\\\x00\n\r")
	}
	for _, name := range expected {
		if !valid(name) || names[name] {
			return false
		}
		names[name] = true
	}
	for _, name := range observed {
		if !valid(name) || !names[name] {
			return false
		}
		delete(names, name)
	}
	return len(names) == 0
}

func (b *lioBackend) checkTopology(ctx context.Context) error {
	if b == nil || ctx == nil || ctx.Err() != nil || !b.prepared || !b.started || len(b.topology) == 0 || b.checkEntries() != nil {
		return ErrReview
	}
	for _, roster := range b.topology {
		if ctx.Err() != nil || len(roster.names) > lioRosterLimit {
			return ErrReview
		}
		id, err := lioConfigIdentity(roster.directory, true)
		if err != nil {
			return ErrReview
		}
		// A new open description starts at offset zero on EVERY observation.
		// dup would share the retained directory's offset and could hide entries.
		fd, err := unix.Openat2(int(roster.directory.Fd()), ".", &unix.OpenHow{
			Flags:   unix.O_RDONLY | unix.O_DIRECTORY | unix.O_CLOEXEC | unix.O_NOFOLLOW,
			Resolve: unix.RESOLVE_BENEATH | unix.RESOLVE_NO_SYMLINKS | unix.RESOLVE_NO_MAGICLINKS | unix.RESOLVE_NO_XDEV,
		})
		if err != nil {
			return ErrReview
		}
		current := os.NewFile(uintptr(fd), "owned-lio-roster-observation")
		observedID, observeErr := lioConfigIdentity(current, true)
		entries, readErr := current.ReadDir(lioRosterLimit + 1)
		end, endErr := current.ReadDir(1)
		closeErr := current.Close()
		finalID, finalErr := lioConfigIdentity(roster.directory, true)
		if observeErr != nil || observedID != id || readErr != nil && !errors.Is(readErr, io.EOF) ||
			len(entries) > lioRosterLimit || len(end) != 0 || !errors.Is(endErr, io.EOF) || closeErr != nil ||
			finalErr != nil || finalID != id || ctx.Err() != nil {
			return ErrReview
		}
		names := make([]string, len(entries))
		for i, entry := range entries {
			names[i] = entry.Name()
		}
		if !lioExactNames(roster.names, names) {
			return ErrReview
		}
	}
	return b.checkEntries()
}
