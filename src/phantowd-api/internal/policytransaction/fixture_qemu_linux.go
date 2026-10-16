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
	"path/filepath"
	"strings"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"golang.org/x/sys/unix"
)

func fixtureRevision(c *naspolicy.Config, n uint64) {
	c.Revision = n
	c.FileServices.Revision = n
	c.FileServices.Shares.Revision = n
	c.FileServices.NFS.Revision = n
	c.FileServices.NFS.VolumeRevision = n
	c.ISCSI.Revision = n
	c.ISCSI.VolumeRevision = n
}
func actualLocksHeld(w *writer) bool {
	f, err := rootOpen(unix.AT_FDCWD, w.path, unix.RESOLVE_NO_SYMLINKS|unix.RESOLVE_NO_MAGICLINKS)
	if err != nil {
		return false
	}
	lockErr := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
	if f.Close() != nil || !errors.Is(lockErr, unix.EWOULDBLOCK) {
		return false
	}
	p, err := naspolicystore.Open(filepath.Join(w.path, "policy"))
	if p != nil {
		_ = p.Close()
		return false
	}
	if err != naspolicystore.ErrBusy {
		return false
	}
	j, err := revisionstore.OpenWithCodec(filepath.Join(w.path, "operations"), operationCodec())
	if j != nil {
		_ = j.Close()
		return false
	}
	return err == revisionstore.ErrBusy
}
func fixtureSnapshot(w *writer) ([][]byte, error) {
	var out [][]byte
	for _, name := range []string{"policy/nas-services.json", "policy/.nas-services.pending", "operations/operation.json", "operations/.operation.pending"} {
		data, err := os.ReadFile(filepath.Join(w.path, name))
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return nil, ErrReview
		}
		out = append(out, data)
	}
	return out, nil
}

// ExerciseTemporaryQEMU is the only external entry point. It accepts invented
// policy DATA, not paths/backends. All writes are to new tmpfs directories;
// there is no existing-state opener, product install or NAS activation.
func ExerciseTemporaryQEMU(ctx context.Context, provided naspolicy.Config) error {
	if ctx == nil || provided.Validate() != nil || len(provided.FileServices.Shares.Shares) == 0 || len(provided.FileServices.NFS.Exports) == 0 || len(provided.ISCSI.Targets) == 0 {
		return ErrInvalid
	}
	encoded, err := json.Marshal(provided)
	if err != nil {
		return ErrInvalid
	}
	defer clear(encoded)
	initial, err := naspolicy.Decode(bytes.NewReader(encoded))
	if err != nil {
		return ErrInvalid
	}
	fixtureRevision(&initial, 1)
	base, _ := json.Marshal(initial)
	defer clear(base)
	next, err := naspolicy.Decode(bytes.NewReader(base))
	if err != nil {
		return ErrInvalid
	}
	fixtureRevision(&next, 2)
	candidate, _ := json.Marshal(next)
	defer clear(candidate)
	for _, scenario := range []string{"normal", "root-drift", "intent-before", "intent-after", "policy-before", "policy-after", "receipt-before", "receipt-after",
		"cancel-before-intent", "cancel-after-intent", "cancel-after-policy", "cancel-after-readback", "cancel-after-receipt", "root-restore-after-intent", "readback-mismatch", "readback-error", "policy-drift-before-receipt", "policy-drift-after-receipt"} {
		if err := exerciseScenario(ctx, scenario, initial, next, base, candidate); err != nil {
			return fmt.Errorf("policy transaction fixture %s: %w", scenario, err)
		}
	}
	return ctx.Err()
}
func exerciseScenario(parent context.Context, scenario string, initial, next naspolicy.Config, base, candidate []byte) (result error) {
	const installation = "11111111222233334444555555555555"
	stage := "construct"
	defer func() {
		if result != nil {
			result = fmt.Errorf("stage=%s: %w", stage, result)
		}
	}()
	beforeFDs, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrReview
	}
	w, err := newDisposable(parent, installation, initial)
	if w != nil {
		defer func() {
			if w.close() != nil {
				result = ErrReview
				return
			}
			if w.discard() != nil {
				result = ErrReview
				return
			}
			after, e := os.ReadDir("/proc/self/fd")
			if e != nil || len(after) != len(beforeFDs) {
				result = ErrReview
			}
		}()
	}
	if err != nil {
		return err
	}
	if !actualLocksHeld(w) {
		return ErrReview
	}
	stage = "privacy-and-copy"
	copyWriter := *w
	if _, err := copyWriter.execute(parent, next); err != ErrInvalid {
		return ErrReview
	}
	for _, value := range []any{w, *w, localOutcome{revision: 2}} {
		if _, err := json.Marshal(value); !errors.Is(err, ErrPrivate) || strings.Contains(fmt.Sprintf("%+v", value), installation) {
			return ErrReview
		}
	}
	policyCalls := 0
	journalCalls := [2]int{}
	policyWrite, journalWrite, policyRead := w.policyWrite, w.journalWrite, w.policyRead
	w.policyWrite = func(rev uint64, c naspolicy.Config) error {
		policyCalls++
		if !actualLocksHeld(w) || !w.attempted {
			return ErrReview
		}
		// Independently observe complete durable-intent Store bytes before any
		// policy call. This is a syscall-return ordering test, not power-loss proof.
		b, raw, e := w.journal.LoadExact()
		defer b.clear()
		defer clear(raw)
		if e != nil || b.revision != 1 || !bytes.Equal(b.base, base) {
			return ErrReview
		}
		if scenario == "policy-before" {
			return ErrReview
		}
		e = policyWrite(rev, c)
		if scenario == "policy-after" && e == nil {
			return ErrReview
		}
		return e
	}
	w.journalWrite = func(rev uint64, b bundle) error {
		if rev > 1 {
			return ErrReview
		}
		journalCalls[rev]++
		if !actualLocksHeld(w) || !w.attempted {
			return ErrReview
		}
		if rev == 0 && policyCalls != 0 || rev == 1 && policyCalls != 1 {
			return ErrReview
		}
		if scenario == "intent-before" && rev == 0 || scenario == "receipt-before" && rev == 1 {
			return ErrReview
		}
		e := journalWrite(rev, b)
		if e == nil && (scenario == "intent-after" && rev == 0 || scenario == "receipt-after" && rev == 1) {
			return ErrReview
		}
		return e
	}
	reads := 0
	w.policyRead = func() (naspolicy.Config, []byte, error) {
		reads++
		c, b, e := policyRead()
		if reads == 2 && e == nil {
			if scenario == "readback-mismatch" {
				b = append(b, '\n')
			}
			if scenario == "readback-error" {
				clear(b)
				return naspolicy.Config{}, nil, ErrReview
			}
		}
		return c, b, e
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	extra := filepath.Join(w.path, "unknown")
	boundaryFailure := false
	w.boundary = func(name string) {
		if scenario == "cancel-"+name {
			cancel()
		}
		if scenario == "root-restore-after-intent" && name == "after-intent" {
			if os.WriteFile(extra, []byte("synthetic"), 0600) != nil || os.Remove(extra) != nil {
				boundaryFailure = true
			}
		}
		if scenario == "policy-drift-before-receipt" && name == "before-receipt" || scenario == "policy-drift-after-receipt" && name == "after-receipt" {
			changed := append(bytes.Clone(candidate), '\n')
			if os.WriteFile(filepath.Join(w.path, "policy/nas-services.json"), changed, 0600) != nil {
				boundaryFailure = true
			}
		}
	}
	if scenario == "root-drift" {
		if os.WriteFile(extra, []byte("synthetic"), 0600) != nil {
			return ErrReview
		}
	}
	if scenario == "normal" {
		stage = "pre-effect-and-concurrent-execute"
		pre, c := context.WithCancel(parent)
		c()
		if _, e := w.execute(pre, next); !errors.Is(e, context.Canceled) || w.attempted {
			return ErrReview
		}
		if _, e := w.execute(parent, initial); e != ErrInvalid || w.attempted {
			return ErrReview
		}
		// Two simultaneous requests share one lifetime and one mutation attempt.
		type answer struct {
			out localOutcome
			err error
		}
		answers := make(chan answer, 2)
		for range 2 {
			go func() { out, e := w.execute(ctx, next); answers <- answer{out, e} }()
		}
		first, second := <-answers, <-answers
		if first.err != nil {
			first, second = second, first
		}
		if first.err != nil || first.out.revision != 2 || second.err != ErrAttempted || !w.confirmed || w.review {
			return ErrReview
		}
	} else {
		stage = "expected-review"
		out, e := w.execute(ctx, next)
		if !errors.Is(e, ErrReview) || out.revision != 0 || !w.review || w.confirmed {
			return ErrReview
		}
		if strings.HasPrefix(scenario, "cancel-") && !errors.Is(e, context.Canceled) {
			return ErrReview
		}
	}
	if boundaryFailure {
		return ErrReview
	}
	if scenario == "root-drift" {
		if os.Remove(extra) != nil {
			return ErrReview
		}
	}
	// Check actual resulting file phases independently, not just counters/result.
	stage = "file-phase-observation"
	snap, err := fixtureSnapshot(w)
	if err != nil {
		return err
	}
	policyRevision := uint64(1)
	journalRevision := uint64(1)
	wantCalls := [2]int{1, 0}
	wantPolicyCalls := 0
	switch scenario {
	case "root-drift":
		journalRevision = 0
		wantCalls = [2]int{}
	case "cancel-before-intent":
		journalRevision = 0
		wantCalls = [2]int{}
	case "intent-before":
		journalRevision = 0
	case "intent-after", "cancel-after-intent", "root-restore-after-intent":
	case "policy-before":
		wantPolicyCalls = 1
	default:
		policyRevision = 2
		wantPolicyCalls = 1
	}
	if scenario == "normal" || scenario == "receipt-after" || scenario == "cancel-after-receipt" || scenario == "policy-drift-after-receipt" {
		journalRevision = 2
		wantCalls[1] = 1
	}
	if scenario == "receipt-before" {
		wantCalls[1] = 1
	}
	if policyCalls != wantPolicyCalls || journalCalls != wantCalls || snap[1] != nil || snap[3] != nil {
		return ErrReview
	}
	policy, err := naspolicy.Decode(bytes.NewReader(snap[0]))
	if err != nil || policy.Revision != policyRevision {
		return ErrReview
	}
	if journalRevision == 0 {
		if snap[2] != nil {
			return ErrReview
		}
	} else {
		b, e := decodeBundle(bytes.NewReader(snap[2]))
		if e != nil {
			return ErrReview
		}
		defer b.clear()
		if b.revision != journalRevision || !bytes.Equal(b.base, base) {
			return ErrReview
		}
		rc := policyevidence.Slot{State: policyevidence.Absent}
		if journalRevision == 2 {
			rc = policyevidence.Slot{State: policyevidence.Present, Data: b.receipt}
		}
		d, e := policyevidence.Match(policyevidence.Evidence{InstallationID: installation, Current: policyevidence.Slot{State: policyevidence.Present, Data: snap[0]}, Intent: policyevidence.Slot{State: policyevidence.Present, Data: b.intent}, Receipt: rc})
		want := policyevidence.IntentBaseObserved
		if policyRevision == 2 {
			want = policyevidence.PublicationUnconfirmed
			if journalRevision == 2 {
				want = policyevidence.LocalConfirmationObserved
			}
		}
		if strings.HasPrefix(scenario, "policy-drift-") {
			want = policyevidence.InconsistentEvidence
		}
		if e != nil || d.Kind() != want {
			return ErrReview
		}
	}
	// A fresh context, restored namespace or new proposed revision cannot retry.
	stage = "retry-refusal"
	beforePolicy, beforeJournal := policyCalls, journalCalls
	if _, e := w.execute(parent, next); scenario == "normal" && e != ErrAttempted || scenario != "normal" && !errors.Is(e, ErrReview) {
		return ErrReview
	}
	after, e := fixtureSnapshot(w)
	if e != nil || policyCalls != beforePolicy || journalCalls != beforeJournal {
		return ErrReview
	}
	for i := range snap {
		if !bytes.Equal(snap[i], after[i]) {
			return ErrReview
		}
	}
	return parent.Err()
}
