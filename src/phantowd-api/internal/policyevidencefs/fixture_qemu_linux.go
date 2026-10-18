//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
	"golang.org/x/sys/unix"
)

// ExerciseTemporaryQEMU is fixture-only, absent from non-QEMU product builds.
// Only freshly generated tmpfs files and self-bind mounts are changed. The
// observer itself remains read-only; this does not qualify any physical medium.
func ExerciseTemporaryQEMU(ctx context.Context, c naspolicy.Config) (result error) {
	const installation = "11111111222233334444555555555555"
	var fs unix.Statfs_t
	if ctx == nil || unix.Statfs("/tmp", &fs) != nil || fs.Type != unix.TMPFS_MAGIC || c.Validate() != nil ||
		len(c.FileServices.Shares.Shares) == 0 || len(c.FileServices.NFS.Exports) == 0 || len(c.ISCSI.Targets) == 0 {
		return ErrInvalid
	}
	if err := policytransaction.ExerciseTemporaryQEMU(ctx, c); err != nil {
		return err
	}
	revision := func(n uint64) {
		c.Revision = n
		c.FileServices.Revision = n
		c.FileServices.Shares.Revision = n
		c.FileServices.NFS.Revision = n
		c.FileServices.NFS.VolumeRevision = n
		c.ISCSI.Revision = n
		c.ISCSI.VolumeRevision = n
	}
	revision(1)
	base, err := json.Marshal(c)
	if err != nil {
		return ErrInvalid
	}
	revision(2)
	current, err := json.Marshal(c)
	if err != nil || c.Validate() != nil {
		return ErrInvalid
	}
	prepared, err := policyevidence.Prepare(installation, base, c)
	if err != nil {
		return err
	}
	baseCopy, err := prepared.BaseBytes()
	if err != nil || !bytes.Equal(baseCopy, base) {
		return ErrInvalid
	}
	candidateCopy, err := prepared.CandidateBytes()
	if err != nil || !bytes.Equal(candidateCopy, current) {
		return ErrInvalid
	}
	baseCopy[0] = '!'
	candidateCopy[0] = '!'
	baseAgain, _ := prepared.BaseBytes()
	candidateAgain, _ := prepared.CandidateBytes()
	if !bytes.Equal(baseAgain, base) || !bytes.Equal(candidateAgain, current) {
		return ErrInvalid
	}
	if _, err := json.Marshal(prepared); !errors.Is(err, policyevidence.ErrPrivate) {
		return ErrInvalid
	}
	i, err := prepared.Intent()
	if err != nil {
		return err
	}
	intent, err := policyevidence.EncodeIntent(i)
	if err != nil {
		return err
	}
	// Invented local-confirmation evidence for matcher tests, NOT a real receipt
	// or preparation result. RawMessage preserves exact uint64 representations.
	var r map[string]json.RawMessage
	if json.Unmarshal(intent, &r) != nil {
		return ErrInvalid
	}
	r["format"], r["phase"] = json.RawMessage(`"phantowd-nas-policy-receipt"`), json.RawMessage(`"local-confirmed"`)
	receipt, _ := json.Marshal(r)
	root, err := os.MkdirTemp("/tmp", "phantowd-policy-evidence-")
	if err != nil {
		return ErrIO
	}
	mounted := ""
	defer func() {
		if mounted != "" {
			result = ErrReview
			return
		}
		if os.RemoveAll(root) != nil {
			result = ErrIO
		}
	}()
	makeLayout := func(name string, cur, in, rc []byte) (string, error) {
		dir := filepath.Join(root, name)
		if os.Mkdir(dir, 0700) != nil {
			return "", ErrIO
		}
		for _, child := range []string{"policy", "operations"} {
			if os.Mkdir(filepath.Join(dir, child), 0700) != nil {
				return "", ErrIO
			}
		}
		for name, data := range map[string][]byte{"policy/nas-services.json": cur, "operations/intent.json": in, "operations/receipt.json": rc} {
			if data != nil && os.WriteFile(filepath.Join(dir, name), data, 0600) != nil {
				return "", ErrIO
			}
		}
		return dir, nil
	}
	// Codec parity only, not a journal transaction or durable confirmation.
	if err := exerciseCloseFaultMatrixQEMU(ctx, 6, func(boundary int, after bool) (*Observer, error) {
		dir, err := makeLayout(fmt.Sprintf("close-%d-%t", boundary, after), current, intent, receipt)
		if err != nil {
			return nil, err
		}
		return Open(ctx, dir, installation)
	}); err != nil {
		return err
	}
	if err := exerciseBundleObservationQEMU(ctx, root, base, current, intent, receipt); err != nil {
		return err
	}
	if err := exerciseHistoryObservationQEMU(ctx, root, base, current, intent, receipt); err != nil {
		return err
	}
	parity, err := makeLayout("preparation-store-parity", base, nil, nil)
	if err != nil {
		return err
	}
	store, err := naspolicystore.Open(filepath.Join(parity, "policy"))
	if err != nil {
		return err
	}
	defer store.Close()
	if err := store.Commit(1, c); err != nil {
		return err
	}
	if store.Close() != nil {
		return ErrReview
	}
	persisted, err := os.ReadFile(filepath.Join(parity, "policy/nas-services.json"))
	if err != nil || !bytes.Equal(persisted, current) {
		return ErrReview
	}
	if d, err := policyevidence.Match(policyevidence.Evidence{InstallationID: installation, Current: policyevidence.Slot{State: policyevidence.Present, Data: persisted}, Intent: policyevidence.Slot{State: policyevidence.Present, Data: intent}, Receipt: policyevidence.Slot{State: policyevidence.Absent}}); err != nil || d.Kind() != policyevidence.PublicationUnconfirmed {
		return ErrReview
	}
	anchored, err := makeLayout("anchored-store-prerequisite", base, nil, nil)
	if err != nil {
		return err
	}
	if err := exerciseAnchoredStore(ctx, anchored, current, c); err != nil {
		return err
	}
	for i, tc := range []struct {
		current, intent, receipt []byte
		kind                     policyevidence.Kind
	}{
		{current, nil, nil, policyevidence.NoRecordedOperation}, {base, intent, nil, policyevidence.IntentBaseObserved},
		{current, intent, nil, policyevidence.PublicationUnconfirmed}, {current, intent, receipt, policyevidence.LocalConfirmationObserved},
		{base, intent, receipt, policyevidence.InconsistentEvidence}, {nil, intent, receipt, policyevidence.IncompleteEvidence},
	} {
		dir, err := makeLayout(string(rune('a'+i)), tc.current, tc.intent, tc.receipt)
		if err != nil {
			return err
		}
		a, err := Open(ctx, dir, installation)
		if err != nil {
			if a != nil {
				a.Close()
			}
			return err
		}
		defer a.Close()
		beforeFDs, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			return ErrIO
		}
		for range 4 {
			d, err := a.Observe(ctx)
			if err != nil || d.Kind() != tc.kind {
				a.Close()
				return ErrReview
			}
			writer, err := naspolicystore.Open(filepath.Join(dir, "policy"))
			if writer != nil {
				writer.Close()
			}
			if !errors.Is(err, naspolicystore.ErrBusy) {
				a.Close()
				return ErrReview
			}
		}
		afterFDs, err := os.ReadDir("/proc/self/fd")
		if err != nil || len(afterFDs) != len(beforeFDs) {
			return ErrReview
		}
		if a.Close() != nil {
			return ErrReview
		}
		writer, err := naspolicystore.Open(filepath.Join(dir, "policy"))
		if err != nil {
			return ErrReview
		}
		if writer.Close() != nil {
			return ErrReview
		}
	}
	for i, relative := range []string{".", "policy", "operations", "policy/nas-services.json"} {
		dir, err := makeLayout("mount-"+string(rune('a'+i)), current, intent, receipt)
		if err != nil {
			return err
		}
		a, err := Open(ctx, dir, installation)
		if err != nil {
			return err
		}
		defer a.Close()
		target := filepath.Join(dir, relative)
		if unix.Mount(target, target, "", unix.MS_BIND, "") != nil {
			a.Close()
			return ErrIO
		}
		mounted = target
		d, observeErr := a.Observe(ctx)
		if unix.Unmount(target, 0) != nil {
			return ErrReview
		}
		mounted = ""
		if d.Kind() != "" || !errors.Is(observeErr, ErrReview) {
			a.Close()
			return ErrReview
		}
		if d, err := a.Observe(ctx); d.Kind() != "" || !errors.Is(err, ErrReview) {
			a.Close()
			return ErrReview
		}
		if a.Close() != nil {
			return ErrReview
		}
	}
	for _, scenario := range []string{"pending", "write-close", "cancel", "read-failure"} {
		dir, err := makeLayout(scenario, current, intent, receipt)
		if err != nil {
			return err
		}
		if scenario == "pending" && os.WriteFile(filepath.Join(dir, "policy/.nas-services.pending"), []byte("not parsed"), 0600) != nil {
			return ErrIO
		}
		a, err := Open(ctx, dir, installation)
		if err != nil {
			return err
		}
		defer a.Close()
		local, cancel := context.WithCancelCause(ctx)
		defer cancel(nil)
		switch scenario {
		case "write-close":
			f, err := os.OpenFile(filepath.Join(dir, "policy/nas-services.json"), os.O_WRONLY, 0)
			if err != nil {
				return ErrIO
			}
			if f.Close() != nil {
				return ErrIO
			}
		case "cancel":
			a.state.beforeMatch = func() { cancel(errors.New("private synthetic context cause")) }
		case "read-failure":
			a.state.readAt = func(*os.File, []byte, int64) (int, error) { return 0, unix.EIO }
		case "pending":
			a.state.readAt = func(*os.File, []byte, int64) (int, error) { return 0, errors.New("pending must not be read") }
		}
		d, observeErr := a.Observe(local)
		cancel(nil)
		if d.Kind() != "" || !errors.Is(observeErr, ErrReview) {
			a.Close()
			return ErrReview
		}
		if scenario == "cancel" && !errors.Is(observeErr, context.Canceled) {
			a.Close()
			return ErrReview
		}
		a.state.beforeMatch = nil
		if d, err := a.Observe(ctx); d.Kind() != "" || !errors.Is(err, ErrReview) {
			a.Close()
			return ErrReview
		}
		writer, err := naspolicystore.Open(filepath.Join(dir, "policy"))
		if writer != nil {
			writer.Close()
		}
		if !errors.Is(err, naspolicystore.ErrBusy) {
			a.Close()
			return ErrReview
		}
		if a.Close() != nil {
			return ErrReview
		}
	}
	for i, mutate := range []func(string) error{
		func(r string) error { return os.WriteFile(filepath.Join(r, "unexpected"), []byte("x"), 0600) },
		func(r string) error { return os.WriteFile(filepath.Join(r, "policy/intent.json"), []byte("x"), 0600) },
		func(r string) error {
			return os.WriteFile(filepath.Join(r, "operations/unexpected"), []byte("x"), 0600)
		},
		func(r string) error { return os.Chmod(filepath.Join(r, "policy/nas-services.json"), 0644) },
		func(r string) error { return os.WriteFile(filepath.Join(r, "operations/intent.json"), []byte{}, 0600) },
		func(r string) error {
			return os.WriteFile(filepath.Join(r, "operations/intent.json"), make([]byte, 4097), 0600)
		},
		func(r string) error { return unix.Mkfifo(filepath.Join(r, "operations/intent.json"), 0600) },
		func(r string) error {
			return os.Symlink(filepath.Join(r, "policy/nas-services.json"), filepath.Join(r, "operations/intent.json"))
		},
		func(r string) error {
			return os.Link(filepath.Join(r, "policy/nas-services.json"), filepath.Join(r, "operations/intent.json"))
		},
	} {
		dir, err := makeLayout("unsafe-"+string(rune('a'+i)), current, nil, nil)
		if err != nil {
			return err
		}
		if mutate(dir) != nil {
			return ErrIO
		}
		a, err := Open(ctx, dir, installation)
		if a != nil {
			a.Close()
		}
		if err == nil {
			return ErrReview
		}
	}
	dir, err := makeLayout("private-concurrent", current, intent, receipt)
	if err != nil {
		return err
	}
	a, err := Open(ctx, dir, installation)
	if err != nil {
		return err
	}
	defer a.Close()
	copied := *a
	if _, err := copied.Observe(ctx); err != ErrInvalid || copied.Close() != ErrInvalid {
		return ErrReview
	}
	for _, v := range []any{a, *a} {
		if _, err := json.Marshal(v); err == nil {
			return ErrReview
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, dir) || strings.Contains(s, installation) || !strings.Contains(s, "private") {
				return ErrReview
			}
		}
	}
	var wg sync.WaitGroup
	failures := make(chan bool, 12)
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d, err := a.Observe(ctx)
			failures <- err != nil || d.Kind() != policyevidence.LocalConfirmationObserved
		}()
	}
	wg.Wait()
	close(failures)
	for failed := range failures {
		if failed {
			return ErrReview
		}
	}
	if a.Close() != nil {
		return ErrReview
	}
	for _, scenario := range []string{"watch-loss", "close-uncertainty"} {
		dir, err := makeLayout(scenario, current, intent, receipt)
		if err != nil {
			return err
		}
		a, err := Open(ctx, dir, installation)
		if err != nil {
			return err
		}
		if scenario == "watch-loss" {
			// A known test-only watch loss, not an ambiguous raw-close retry.
			if unix.Close(a.state.watch) != nil {
				return ErrIO
			}
			a.state.watch = -1
			if d, err := a.Observe(ctx); d.Kind() != "" || !errors.Is(err, ErrReview) {
				a.Close()
				return ErrReview
			}
			if a.Close() != nil {
				return ErrReview
			}
			continue
		}
		// Controlled close fault performs NO syscall. Real close errors do not
		// prove that the kernel kept the lock; product code never retries them.
		calls := 0
		faulted := a.state.files[2].file
		a.state.closeFile = func(f *os.File) error {
			if f == faulted {
				calls++
				return unix.EIO
			}
			return f.Close()
		}
		first, second := a.Close(), a.Close()
		writer, writerErr := naspolicystore.Open(filepath.Join(dir, "policy"))
		if writer != nil {
			writer.Close()
		}
		_, observeErr := a.Observe(ctx)
		good := first == ErrReview && second == ErrReview && calls == 1 && errors.Is(writerErr, naspolicystore.ErrBusy) && errors.Is(observeErr, ErrReview)
		// Only this fixture knows its injected close did not touch the FD.
		// Settle the known-open synthetic objects without resuming the Owner.
		for _, roster := range [][]object{a.state.files[:], a.state.directoryObjects()} {
			for _, o := range roster {
				if o.file != nil && o.file.Close() != nil {
					good = false
				}
			}
		}
		if unix.Close(a.state.watch) != nil {
			good = false
		}
		if !good {
			return ErrReview
		}
	}
	return ctx.Err()
}
