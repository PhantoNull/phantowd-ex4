//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
)

func copyViewFixture(c naspolicy.Config) (naspolicy.Config, error) {
	wire, err := json.Marshal(c)
	if err != nil {
		return naspolicy.Config{}, ErrInvalid
	}
	return naspolicy.Decode(bytes.NewReader(wire))
}

// Validate fixture proposals without needing a privileged/unique-mount host.
func draftViewFixture(base naspolicy.Config, revision uint64, files bool) (naspolicy.Config, error) {
	c, err := copyViewFixture(base)
	if err != nil {
		return naspolicy.Config{}, err
	}
	if len(c.FileServices.Shares.Shares) == 0 || len(c.FileServices.NFS.Exports) == 0 || len(c.ISCSI.Backings) == 0 {
		return naspolicy.Config{}, ErrInvalid
	}
	fixtureRevision(&c, revision)
	if files {
		c.FileServices.Shares.Shares[0].RelativePath = fmt.Sprintf("books-revision-%d", revision)
		// Exercise a real NFS definition edit without reassigning its stable
		// export identity to another root. Rebinding is a separate refusal case.
		client := &c.FileServices.NFS.Exports[0].Clients[0]
		if client.Access == "ro" {
			client.Access = "rw"
		} else {
			client.Access = "ro"
		}
	} else {
		c.ISCSI.Backings[0].RelativePath = fmt.Sprintf("luns/reference-revision-%d.img", revision)
	}
	if c.Validate() != nil {
		return naspolicy.Config{}, ErrInvalid
	}
	return c, nil
}

// Fresh synthetic tmpfs state only, through the existing transaction path.
// No existing-state opener, credential/backing access or product writer.
func exerciseHistoryViewEdits(ctx context.Context, initial naspolicy.Config) (result error) {
	stage := "construct"
	defer func() {
		if result != nil {
			result = fmt.Errorf("view fixture %s: %w", stage, result)
		}
	}()
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrReview
	}
	w, err := newDisposableHistory(ctx, "11111111222233334444555555555555", initial)
	if err != nil {
		if w != nil && w.close() != nil {
			return ErrReview
		}
		return err
	}
	defer func() {
		if w.close() != nil || w.discard() != nil {
			result = ErrReview
			return
		}
		after, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(after) != len(before) {
			result = ErrReview
		}
	}()
	// Nonempty cross-protocol content is essential: empty-policy success cannot
	// show that a view preserved another protocol's complete definitions.
	if len(initial.FileServices.Shares.Shares) == 0 || len(initial.FileServices.Shares.Shares[0].Grants) == 0 ||
		len(initial.FileServices.NFS.Exports) == 0 || len(initial.ISCSI.Targets) == 0 ||
		len(initial.ISCSI.Targets[0].LUNs) == 0 || len(initial.ISCSI.Targets[0].Initiators) == 0 ||
		len(initial.ISCSI.Targets[0].Initiators[0].Grants) == 0 || len(initial.ISCSI.Backings) == 0 {
		return ErrInvalid
	}
	root, history := w.root.Fd(), w.history.dir.Fd()
	stage = "file-service-commit-readback"
	next, err := draftViewFixture(initial, 2, true)
	if err != nil {
		return err
	}
	if got, err := w.executeFileServicesHistory(ctx, 1, next.FileServices); err != nil || got.revision != 2 {
		return ErrReview
	}
	current, _, err := w.policyRead()
	if err != nil || !reflect.DeepEqual(current, next) || !actualLocksHeld(w) {
		return ErrReview
	}
	var firstName string
	var first journalObject
	for firstName, first = range w.history.records {
		break
	}
	if firstName == "" {
		return ErrReview
	}
	firstWire := bytes.Clone(first.wire)
	defer clear(firstWire)
	stage = "iscsi-commit-readback"
	next, err = draftViewFixture(next, 3, false)
	if err != nil {
		return err
	}
	if got, err := w.executeISCSIHistory(ctx, 2, next.ISCSI); err != nil || got.revision != 3 {
		return ErrReview
	}
	current, _, err = w.policyRead()
	if err != nil || !reflect.DeepEqual(current, next) || !w.historyMatches(w.base) {
		return ErrReview
	}
	snapshot, err := historyWriterSnapshot(w)
	if err != nil {
		return err
	}
	// Stale expected revision, referenced-volume rebinding and pre-admission
	// cancellation leave policy AND the complete record census byte-identical.
	stage = "stale-refusal"
	if got, err := w.executeFileServicesHistory(ctx, 1, next.FileServices); err != ErrInvalid || got.revision != 0 {
		return ErrReview
	}
	bad, err := copyViewFixture(next)
	if err != nil {
		return err
	}
	fixtureRevision(&bad, 4)
	stage = "volume-rebind-refusal"
	for i := range bad.FileServices.Shares.Volumes {
		if bad.FileServices.Shares.Volumes[i].ID == bad.ISCSI.Backings[0].VolumeID {
			bad.FileServices.Shares.Volumes[i].FilesystemUUID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
		}
	}
	if got, err := w.executeFileServicesHistory(ctx, 3, bad.FileServices); err != ErrInvalid || got.revision != 0 {
		return ErrReview
	}
	canceled, cancel := context.WithCancel(ctx)
	stage = "pre-cancel-refusal"
	cancel()
	if got, err := w.executeISCSIHistory(canceled, 3, next.ISCSI); !errors.Is(err, context.Canceled) || got.revision != 0 {
		return ErrReview
	}
	after, err := historyWriterSnapshot(w)
	if err != nil || !equalHistorySnapshot(snapshot, after) || w.review {
		return ErrReview
	}
	// Two DIFFERENT protocol edits based on revision3 race under one owner. Only
	// one can publish4; the losing view cannot overwrite the winner's revision.
	files, err := draftViewFixture(next, 4, true)
	stage = "different-view-concurrent-winner"
	if err != nil {
		return err
	}
	iscsi, err := draftViewFixture(next, 4, false)
	if err != nil {
		return err
	}
	var outcomes [2]localOutcome
	var failures [2]error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		outcomes[0], failures[0] = w.executeFileServicesHistory(ctx, 3, files.FileServices)
	}()
	go func() { defer wg.Done(); outcomes[1], failures[1] = w.executeISCSIHistory(ctx, 3, iscsi.ISCSI) }()
	wg.Wait()
	winner := -1
	for i := range outcomes {
		if failures[i] == nil && outcomes[i].revision == 4 {
			if winner != -1 {
				return ErrReview
			}
			winner = i
		} else if failures[i] != ErrInvalid || outcomes[i].revision != 0 {
			return ErrReview
		}
	}
	if winner < 0 || len(w.history.records) != 3 || !w.historyMatches(w.base) {
		return ErrReview
	}
	want := files
	if winner == 1 {
		want = iscsi
	}
	current, _, err = w.policyRead()
	if err != nil || !reflect.DeepEqual(current, want) {
		return ErrReview
	}
	// After an actual intent publication, a canceled view poisons this SAME
	// lifetime. Switching protocol/context/operation cannot erase or retry it.
	fixtureRevision(&want, 5)
	stage = "post-intent-review"
	uncertain, stop := context.WithCancel(ctx)
	defer stop()
	w.boundary = func(stage string) {
		if stage == "after-intent" {
			stop()
		}
	}
	got, err := w.executeFileServicesHistory(uncertain, 4, want.FileServices)
	if !errors.Is(err, ErrReview) || !errors.Is(err, context.Canceled) || got.revision != 0 || !w.review {
		return ErrReview
	}
	w.boundary = nil
	snapshot, err = historyWriterSnapshot(w)
	if err != nil {
		return err
	}
	stage = "cross-view-review-refusal"
	for range 2 {
		if got, err := w.executeISCSIHistory(ctx, 4, want.ISCSI); err != ErrReview || got.revision != 0 {
			return ErrReview
		}
		after, err = historyWriterSnapshot(w)
		if err != nil || !equalHistorySnapshot(snapshot, after) {
			return ErrReview
		}
	}
	retained := w.history.records[firstName]
	stage = "retained-originals"
	if w.root.Fd() != root || w.history.dir.Fd() != history || retained.file != first.file || retained.stamp != first.stamp || !bytes.Equal(retained.wire, firstWire) || !actualLocksHeld(w) {
		return ErrReview
	}
	fmt.Println("PHANTOWD_POLICY_VIEW_WRITER_READY commits=3 stale_refused=true cross_protocol_preserved=true uncertainty_fenced=true original_locks=true product=false scope=temporary-qemu-only")
	stage = "verified-disposal"
	return nil
}
