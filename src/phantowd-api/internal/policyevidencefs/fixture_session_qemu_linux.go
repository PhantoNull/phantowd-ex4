//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policytransaction"
	"golang.org/x/sys/unix"
)

var sessionObservationMu sync.Mutex
var retainedSessionObservations []*Observer

// Only synthetic tmpfs files. Declarations are invented fixture DATA, not proof
// of writer completion, restart, historical sync or permission to start services.
func exerciseSessionObservationQEMU(ctx context.Context, base, current []byte, wires [][]byte, names []string) error {
	sessionObservationMu.Lock()
	defer sessionObservationMu.Unlock()
	var fs unix.Statfs_t
	if len(retainedSessionObservations) != 0 {
		return ErrReview
	}
	if ctx == nil || len(wires) != 2 || len(names) != 2 || names[0] == names[1] || unix.Statfs("/tmp", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return ErrInvalid
	}
	for _, name := range names {
		if !policytransaction.IsHistoryRecordName(name) {
			return ErrInvalid
		}
	}
	for _, scenario := range []string{"closed", "open", "missing", "pending-policy", "pending-history", "pending-session", "restored", "malformed", "role-bind", "read-error"} {
		if err := exerciseSessionObservationCase(ctx, scenario, base, current, wires, names); err != nil {
			return fmt.Errorf("session observer %s: %w", scenario, err)
		}
	}
	fmt.Println("PHANTOWD_POLICY_SESSION_FS_READY scenarios=10 original_locks=4 checkpoint_bound=true pending_metadata_only=true restored_refused=true readonly=true admission=false scope=temporary-qemu-only")
	return ctx.Err()
}

type sessionFixtureSnapshot struct {
	data     map[string][]byte
	metadata map[string]unix.Stat_t
}

func readSessionFixtureSnapshot(root string, names []string) (sessionFixtureSnapshot, error) {
	s := sessionFixtureSnapshot{make(map[string][]byte), make(map[string]unix.Stat_t)}
	for _, name := range names {
		p := filepath.Join(root, name)
		var st unix.Stat_t
		if unix.Lstat(p, &st) != nil {
			return s, ErrIO
		}
		if st.Mode&unix.S_IFMT == unix.S_IFREG {
			fd, err := unix.Open(p, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NOATIME|unix.O_CLOEXEC, 0)
			if err != nil {
				return s, ErrIO
			}
			f := os.NewFile(uintptr(fd), "synthetic-session-oracle")
			data, e := io.ReadAll(io.LimitReader(f, policyevidence.MaxHistoryInputBytes+1))
			closeErr := f.Close()
			if e != nil || closeErr != nil || len(data) > policyevidence.MaxHistoryInputBytes {
				return s, ErrIO
			}
			s.data[name] = data
		}
		s.metadata[name] = st
	}
	return s, nil
}

func sessionObserverLocks(root string) bool {
	for _, name := range []string{"", "policy", "operations", "policy-session"} {
		f, err := os.Open(filepath.Join(root, name))
		if err != nil {
			return false
		}
		e := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if f.Close() != nil || !errors.Is(e, unix.EWOULDBLOCK) {
			return false
		}
	}
	return true
}

func exerciseSessionObservationCase(ctx context.Context, scenario string, base, current []byte, wires [][]byte, names []string) (result error) {
	const installation = "11111111222233334444555555555555"
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrIO
	}
	root, err := os.MkdirTemp("/tmp", "phantowd-session-observation-")
	if err != nil {
		return ErrIO
	}
	var a *Observer
	mounted := false
	defer func() {
		if mounted {
			retainedSessionObservations = append(retainedSessionObservations, a)
			result = ErrReview
			return
		}
		if a != nil && (a.state.closeFailed || a.Close() != nil) {
			retainedSessionObservations = append(retainedSessionObservations, a)
			result = ErrReview
			return
		}
		if len(retainedSessionObservations) != 0 {
			result = ErrReview
			return
		}
		// Known-name/nonrecursive disposal only, after verified reference closure.
		paths := []string{"original-epoch", "policy/nas-services.json", "policy/.nas-services.pending", "policy-session/epoch.json", "policy-session/.epoch.pending", "operations/.history.pending"}
		for _, name := range names {
			paths = append(paths, filepath.Join("operations", name))
		}
		for _, name := range paths {
			if e := os.Remove(filepath.Join(root, name)); e != nil && !errors.Is(e, os.ErrNotExist) {
				result = ErrReview
				return
			}
		}
		for _, name := range []string{"policy", "operations", "policy-session", ""} {
			if os.Remove(filepath.Join(root, name)) != nil {
				result = ErrReview
				return
			}
		}
		after, e := os.ReadDir("/proc/self/fd")
		if e != nil || len(after) != len(before) {
			result = ErrReview
		}
	}()
	for _, name := range []string{"policy", "operations", "policy-session"} {
		if os.Mkdir(filepath.Join(root, name), 0700) != nil {
			return ErrIO
		}
	}
	o, err := policyevidence.DeclareEpochOpening(installation, "bbbbbbbbccccddddeeeeffffffffffff", 1, base)
	if err != nil {
		return ErrInvalid
	}
	opening, _ := policyevidence.EncodeEpochOpening(o)
	doc := map[string]any{"format": "phantowd-policy-session-journal-experimental", "schema_version": 1, "revision": 1, "installation_id": installation, "opening": base64.StdEncoding.EncodeToString(opening), "closure": ""}
	if scenario != "open" {
		c, e := policyevidence.DeclareEpochClosure(opening, current)
		if e != nil {
			return ErrInvalid
		}
		closure, _ := policyevidence.EncodeEpochClosure(c)
		doc["revision"], doc["closure"] = 2, base64.StdEncoding.EncodeToString(closure)
	}
	epoch, _ := json.Marshal(doc)
	if scenario == "malformed" {
		epoch = []byte(`{}`)
	}
	if os.WriteFile(filepath.Join(root, "policy/nas-services.json"), current, 0600) != nil {
		return ErrIO
	}
	for i, name := range names {
		if os.WriteFile(filepath.Join(root, "operations", name), wires[i], 0600) != nil {
			return ErrIO
		}
	}
	if scenario != "missing" && os.WriteFile(filepath.Join(root, "policy-session/epoch.json"), epoch, 0600) != nil {
		return ErrIO
	}
	pending := map[string]string{"pending-policy": "policy/.nas-services.pending", "pending-history": "operations/.history.pending", "pending-session": "policy-session/.epoch.pending"}[scenario]
	if pending != "" && os.WriteFile(filepath.Join(root, pending), []byte("never read"), 0600) != nil {
		return ErrIO
	}
	// The old two-role profile must not guess/adopt the new role.
	old, e := OpenHistory(ctx, root, installation, base)
	if old != nil {
		if old.Close() != nil {
			retainedSessionObservations = append(retainedSessionObservations, old)
		}
		return ErrReview
	}
	if !errors.Is(e, ErrUnsafe) {
		return ErrReview
	}
	tracked := []string{"", "policy", "operations", "policy-session", "policy/nas-services.json"}
	for _, name := range names {
		tracked = append(tracked, filepath.Join("operations", name))
	}
	if scenario != "missing" {
		tracked = append(tracked, "policy-session/epoch.json")
	}
	snapshot, err := readSessionFixtureSnapshot(root, tracked)
	if err != nil {
		return err
	}
	checkpoint := bytes.Clone(base)
	a, err = OpenSessionHistory(ctx, root, installation, checkpoint)
	if err != nil {
		return err
	}
	checkpoint[0] = '!'
	if !sessionObserverLocks(root) {
		return ErrReview
	}
	if d, e := a.Observe(ctx); e != ErrInvalid || d.Kind() != "" {
		return ErrReview
	}
	copyObserver := *a
	if d, e := copyObserver.ObserveSession(ctx); e != ErrInvalid || d.Kind() != "" {
		return ErrReview
	}
	reads := 0
	if pending != "" || scenario == "read-error" {
		a.state.readAt = func(*os.File, []byte, int64) (int, error) { reads++; return 0, ErrIO }
	}
	if scenario == "restored" {
		if os.Rename(filepath.Join(root, "policy-session/epoch.json"), filepath.Join(root, "original-epoch")) != nil || os.WriteFile(filepath.Join(root, "policy-session/epoch.json"), epoch, 0600) != nil {
			return ErrIO
		}
	}
	if scenario == "role-bind" {
		path := filepath.Join(root, "policy-session")
		if unix.Mount(path, path, "", unix.MS_BIND, "") != nil {
			return ErrIO
		}
		mounted = true
	}
	for i := 0; i < 2; i++ {
		d, e := a.ObserveSession(ctx)
		want := policyevidence.ClosureSessionHistoryObserved
		if scenario == "open" {
			want = policyevidence.OpenSessionHistoryObserved
		}
		if scenario == "missing" {
			want = policyevidence.IncompleteSessionEvidence
		}
		good := scenario == "closed" || scenario == "open" || scenario == "missing"
		if good {
			if e != nil || d.Kind() != want {
				return ErrReview
			}
		} else if !errors.Is(e, ErrReview) || d.Kind() != "" {
			return ErrReview
		}
		if pending != "" && reads != 0 || scenario == "read-error" && reads != 1 || !sessionObserverLocks(root) {
			return ErrReview
		}
		if i == 0 && scenario == "restored" {
			if os.Remove(filepath.Join(root, "policy-session/epoch.json")) != nil || os.Rename(filepath.Join(root, "original-epoch"), filepath.Join(root, "policy-session/epoch.json")) != nil {
				return ErrIO
			}
		}
		if i == 0 && mounted {
			if unix.Unmount(filepath.Join(root, "policy-session"), 0) != nil {
				return ErrReview
			}
			mounted = false
		}
	}
	if a.Close() != nil {
		return ErrReview
	}
	if scenario != "restored" && scenario != "role-bind" {
		after, e := readSessionFixtureSnapshot(root, tracked)
		if e != nil || !reflect.DeepEqual(snapshot, after) {
			return ErrReview
		}
	}
	return ctx.Err()
}
