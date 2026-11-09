// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"errors"
	"fmt"
	"math"
	"os"
	"strconv"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/volumeregistry"
	"golang.org/x/sys/unix"
)

// One explicit operator operation, not product boot or storage adoption.
// The parent supplies a separately provisioned trusted local directory at slot3.
func commitInheritedVolumeRegistry(expectedText string) error {
	expected, err := strconv.ParseUint(expectedText, 10, 64)
	if err != nil || strconv.FormatUint(expected, 10) != expectedText || expected == math.MaxUint64 {
		return errors.New("invalid explicit registry revision")
	}
	document, err := volumeregistry.Decode(os.Stdin)
	if err != nil || document.Revision != expected+1 {
		return errors.New("invalid explicit registry document")
	}
	// Match the existing inherited-account boundary: never consume a runtime FD.
	flags, err := unix.FcntlInt(3, unix.F_GETFD, 0)
	var info unix.Stat_t
	if err != nil || flags&unix.FD_CLOEXEC != 0 || unix.Fstat(3, &info) != nil || info.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("inherited registry directory unavailable")
	}
	source := os.NewFile(3, "inherited-volume-registry-directory")
	store, openErr := volumeregistry.OpenWriter(source)
	if err := source.Close(); err != nil {
		if store != nil {
			store.Close()
		}
		return errors.New("registry outcome requires operator review")
	}
	if openErr != nil {
		return registryOperatorError(openErr)
	}
	commitErr := store.Commit(expected, document)
	closeErr := store.Close()
	if closeErr != nil || errors.Is(commitErr, revisionstore.ErrUncertain) {
		return errors.New("registry outcome requires operator review")
	}
	if commitErr != nil {
		return registryOperatorError(commitErr)
	}
	if _, err := fmt.Fprintf(os.Stdout, "revision=%d claims=%d\n", document.Revision, len(document.Volumes)); err != nil {
		return errors.New("registry result unavailable; inspect state before retry")
	}
	return nil
}

func registryOperatorError(err error) error {
	switch {
	case errors.Is(err, revisionstore.ErrConflict):
		return errors.New("registry revision conflict")
	case errors.Is(err, revisionstore.ErrBusy):
		return errors.New("registry state busy")
	case errors.Is(err, revisionstore.ErrInvalid):
		return errors.New("registry commit refused")
	default:
		return errors.New("registry state unavailable")
	}
}
