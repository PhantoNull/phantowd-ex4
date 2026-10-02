//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"golang.org/x/sys/unix"
)

func stageRoot(name string) (*os.File, error) {
	fd, err := unix.Open(name, unix.O_PATH|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), "fixed-disposable-stage-root"), nil
}

// Called only after the exact VersatilePB/root/argument guard in main. All
// destinations are fresh fixed directories on the guest's /run tmpfs. Nothing
// here is installed in product startup or accepts operator paths/manifests.
func stageFixture() error {
	files, aliases, err := inputs()
	if err != nil {
		return err
	}
	plan, err := runtimebundle.NewPlan(files, aliases)
	if err != nil {
		return err
	}
	source, err := stageRoot("/")
	if err != nil {
		return err
	}
	defer source.Close()
	destination, err := stageRoot("/run/phantowd-samba-root")
	if err != nil {
		return err
	}
	defer destination.Close()
	if err := plan.StageQEMU(context.Background(), source, destination); err != nil {
		return errors.Join(errors.New("positive staging"), err)
	}
	// Fresh bytes, not hardlinks or aliases to the guest base. The following
	// separate non-root read-only Inspect still validates the complete result.
	for _, file := range files {
		original, err := os.Lstat("/" + file.Path)
		if err != nil {
			return err
		}
		copy, err := os.Lstat("/run/phantowd-samba-root/" + file.Path)
		if err != nil || os.SameFile(original, copy) {
			return errors.New("fresh copy evidence")
		}
	}
	if err := os.Mkdir("/run/phantowd-bundle-rejections", 0700); err != nil {
		return err
	}
	newRoot := func(name string) (*os.File, error) {
		if err := os.Mkdir("/run/phantowd-bundle-rejections/"+name, 0700); err != nil {
			return nil, err
		}
		return stageRoot("/run/phantowd-bundle-rejections/" + name)
	}
	// A pre-existing file must survive unchanged. Neither cleanup nor overwrite
	// is attempted, even though the entire fixture disappears at guest poweroff.
	occupied, err := newRoot("occupied")
	if err != nil {
		return err
	}
	defer occupied.Close()
	const sentinel = "/run/phantowd-bundle-rejections/occupied/sentinel"
	if err := os.WriteFile(sentinel, []byte("unchanged"), 0600); err != nil {
		return err
	}
	if err := plan.StageQEMU(context.Background(), source, occupied); !errors.Is(err, runtimebundle.ErrMismatch) || errors.Is(err, runtimebundle.ErrStageIncomplete) {
		return errors.New("occupied destination refusal")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "unchanged" {
		return errors.New("existing bytes changed")
	}
	// Use the smallest real object to keep failed-copy test memory bounded.
	smallest := files[0]
	for _, file := range files {
		if file.Size < smallest.Size {
			smallest = file
		}
	}
	smallest.SHA256[0] ^= 1
	wrong, err := runtimebundle.NewPlan([]runtimebundle.File{smallest}, nil)
	if err != nil {
		return err
	}
	partial, err := newRoot("partial")
	if err != nil {
		return err
	}
	defer partial.Close()
	if err := wrong.StageQEMU(context.Background(), source, partial); !errors.Is(err, runtimebundle.ErrStageIncomplete) || !errors.Is(err, runtimebundle.ErrMismatch) {
		return errors.New("failed copy disposition")
	}
	if info, err := os.Lstat("/run/phantowd-bundle-rejections/partial/" + smallest.Path); err != nil || info.Mode().Perm() != 0600 {
		return errors.New("failed copy must not be executable")
	}
	if info, err := partial.Stat(); err != nil || info.Mode().Perm() != 0700 {
		return errors.New("failed copy root must remain private")
	}
	// This is a refusal regression, not a retry of the operation. The prototype
	// refuses a second entry on the dirty root before any further writes.
	if err := wrong.StageQEMU(context.Background(), source, partial); !errors.Is(err, runtimebundle.ErrMismatch) || errors.Is(err, runtimebundle.ErrStageIncomplete) {
		return errors.New("partial tree must not resume")
	}
	writable, err := newRoot("writable-source")
	if err != nil {
		return err
	}
	defer writable.Close()
	if err := plan.StageQEMU(context.Background(), writable, writable); !errors.Is(err, runtimebundle.ErrMismatch) || errors.Is(err, runtimebundle.ErrStageIncomplete) {
		return errors.New("writable source refusal")
	}
	canceled, err := newRoot("canceled")
	if err != nil {
		return err
	}
	defer canceled.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := plan.StageQEMU(ctx, source, canceled); !errors.Is(err, context.Canceled) || errors.Is(err, runtimebundle.ErrStageIncomplete) {
		return errors.New("canceled stage refusal")
	}
	if entries, err := os.ReadDir("/run/phantowd-bundle-rejections/canceled"); err != nil || len(entries) != 0 {
		return errors.New("canceled stage wrote entries")
	}
	if len(aliases) == 0 {
		return errors.New("actual source alias required")
	}
	var aliasFile runtimebundle.File
	for _, file := range files {
		if file.Path == aliases[0].Target {
			aliasFile = file
		}
	}
	aliasFile.Path = aliases[0].Path
	aliasPlan, err := runtimebundle.NewPlan([]runtimebundle.File{aliasFile}, nil)
	if err != nil {
		return err
	}
	aliasRoot, err := newRoot("source-alias")
	if err != nil {
		return err
	}
	defer aliasRoot.Close()
	if err := aliasPlan.StageQEMU(context.Background(), source, aliasRoot); !errors.Is(err, runtimebundle.ErrMismatch) {
		return errors.New("source symlink must not be followed")
	}
	fmt.Println("PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only")
	return nil
}
