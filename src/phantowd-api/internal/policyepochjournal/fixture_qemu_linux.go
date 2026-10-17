//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyepochjournal

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

var fixtureMutex sync.Mutex
var retainedFixture []struct {
	journal *Journal
	parent  *os.File
}

func retainFixture(j *Journal, parent *os.File) {
	retainedFixture = append(retainedFixture, struct {
		journal *Journal
		parent  *os.File
	}{j, parent})
}

// Fresh owned tmpfs fixture only. This does not add a role to any existing
// policy/history directory, choose a product state path or open a physical disk.
func ExerciseTemporaryQEMU(ctx context.Context, provided naspolicy.Config) error {
	fixtureMutex.Lock()
	defer fixtureMutex.Unlock()
	if len(retainedFixture) != 0 {
		return ErrReview
	}
	var fs unix.Statfs_t
	if ctx == nil || provided.Validate() != nil || unix.Statfs("/tmp", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return ErrInvalid
	}
	setRevision := func(n uint64) {
		provided.Revision = n
		provided.FileServices.Revision = n
		provided.FileServices.Shares.Revision = n
		provided.FileServices.NFS.Revision = n
		provided.FileServices.NFS.VolumeRevision = n
		provided.ISCSI.Revision = n
		provided.ISCSI.VolumeRevision = n
	}
	setRevision(1)
	base, err := json.Marshal(provided)
	if err != nil {
		return ErrInvalid
	}
	defer clear(base)
	setRevision(2)
	next, err := json.Marshal(provided)
	if err != nil {
		return ErrInvalid
	}
	defer clear(next)
	for _, scenario := range []string{"normal", "opening-cancel", "closure-error"} {
		if err := exerciseScenario(ctx, base, next, scenario); err != nil {
			return fmt.Errorf("session journal %s: %w", scenario, err)
		}
	}
	fmt.Println("PHANTOWD_POLICY_EPOCH_JOURNAL_READY scenarios=3 fresh_only=true actual_store_lock=true exact_readback=true uncertainty_fenced=true private_copies=true declarations_only=true admission=false scope=temporary-qemu-only")
	return ctx.Err()
}

func exerciseScenario(parentCtx context.Context, base, next []byte, scenario string) (result error) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrReview
	}
	root, err := os.MkdirTemp("/tmp", "phantowd-session-role-")
	if err != nil {
		return ErrReview
	}
	role := filepath.Join(root, "policy-session")
	if os.Mkdir(role, 0700) != nil {
		return ErrReview
	}
	parent, err := os.Open(root)
	if err != nil {
		return ErrReview
	}
	j, err := OpenFresh(parentCtx, parent, "11111111222233334444555555555555", math.MaxUint64)
	if err != nil {
		if j == nil {
			_ = parent.Close()
		} else {
			retainFixture(j, parent)
		}
		return ErrReview
	}
	canDispose := true
	defer func() {
		// Only the newly generated, exact known fixture files/empty directories.
		// No recursive cleanup or cleanup after uncertain child closure.
		if !canDispose || j.Close() != nil {
			retainFixture(j, parent)
			result = ErrReview
			return
		}
		if parent.Close() != nil {
			result = ErrReview
			return
		}
		names, err := os.ReadDir(role)
		if err != nil || len(names) != 1 || names[0].Name() != "epoch.json" || !names[0].Type().IsRegular() {
			result = ErrReview
			return
		}
		if os.Remove(filepath.Join(role, "epoch.json")) != nil || os.Remove(role) != nil || os.Remove(root) != nil {
			result = ErrReview
			return
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(before) != len(after) {
			result = ErrReview
		}
	}()
	copy := *j
	for _, value := range []any{j, copy} {
		if strings.Contains(fmt.Sprintf("%#v", value), "11111111222233334444555555555555") {
			return ErrReview
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivate) {
			return ErrReview
		}
	}
	if copy.RecordOpening(parentCtx, base) != ErrInvalid || copy.Close() != ErrInvalid {
		return ErrReview
	}
	other, busyErr := OpenFresh(parentCtx, parent, "11111111222233334444555555555555", 1)
	if other != nil {
		retainFixture(other, parent)
		canDispose = false
		return ErrReview
	}
	if busyErr != ErrBusy {
		return ErrReview
	}
	ctx, cancel := context.WithCancel(parentCtx)
	defer cancel()
	actual := j.state.commit
	if scenario == "opening-cancel" {
		j.state.commit = func(expected uint64, d document) error {
			if err := actual(expected, d); err != nil {
				return err
			}
			cancel()
			return nil
		}
	}
	err = j.RecordOpening(ctx, base)
	if scenario == "opening-cancel" {
		if !errors.Is(err, ErrReview) || !errors.Is(err, context.Canceled) {
			return ErrReview
		}
	} else if err != nil {
		return err
	}
	file := filepath.Join(role, "epoch.json")
	openingWire, err := os.ReadFile(file)
	if err != nil {
		return ErrReview
	}
	openingDoc, err := decodeDocument(bytes.NewReader(openingWire))
	if err != nil || openingDoc.Revision != 1 {
		return ErrReview
	}
	if scenario != "opening-cancel" {
		if d, err := j.Observe(parentCtx, base); err != nil || d.Kind() != policyevidence.OpenEpochObserved {
			return ErrReview
		}
		if scenario == "closure-error" {
			j.state.commit = func(expected uint64, d document) error {
				if err := actual(expected, d); err != nil {
					return err
				}
				return errors.New("private controlled post-commit failure")
			}
		}
		err = j.RecordClosure(ctx, next)
		if scenario == "normal" {
			if err != nil {
				return err
			}
		} else if !errors.Is(err, ErrReview) {
			return ErrReview
		}
		wire, err := os.ReadFile(file)
		if err != nil {
			return ErrReview
		}
		d, err := decodeDocument(bytes.NewReader(wire))
		if err != nil || d.Revision != 2 || d.Opening != openingDoc.Opening {
			return ErrReview
		}
		if observed, err := d.observe(policyevidence.Slot{State: policyevidence.Present, Data: next}); err != nil || observed.Kind() != policyevidence.ClosureMatchesCurrent {
			return ErrReview
		}
		if scenario == "normal" {
			if observed, err := j.Observe(parentCtx, next); err != nil || observed.Kind() != policyevidence.ClosureMatchesCurrent {
				return ErrReview
			}
		}
	}
	retained, err := os.ReadFile(file)
	if err != nil {
		return ErrReview
	}
	if scenario != "normal" {
		for range 2 {
			if j.RecordOpening(parentCtx, base) != ErrReview || j.RecordClosure(parentCtx, next) != ErrReview {
				return ErrReview
			}
			if _, err := j.Observe(parentCtx, next); err != ErrReview {
				return ErrReview
			}
			wire, err := os.ReadFile(file)
			if err != nil || !bytes.Equal(retained, wire) {
				return ErrReview
			}
		}
	}
	if j.Close() != nil {
		return ErrReview
	}
	wire, err := os.ReadFile(file)
	if err != nil || !bytes.Equal(retained, wire) {
		return ErrReview
	}
	other, existingErr := OpenFresh(parentCtx, parent, "11111111222233334444555555555555", 1)
	if other != nil {
		retainFixture(other, parent)
		canDispose = false
		return ErrReview
	}
	if existingErr != ErrExisting {
		return ErrReview
	}
	wire, err = os.ReadFile(file)
	if err != nil || !bytes.Equal(retained, wire) {
		return ErrReview
	}
	return parentCtx.Err()
}
