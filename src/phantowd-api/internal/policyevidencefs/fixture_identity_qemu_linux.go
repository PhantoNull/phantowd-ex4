//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/identityevidence"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

var identityObservationMu sync.Mutex
var retainedIdentityObservers []*Observer

func exerciseIdentityObservationQEMU(ctx context.Context) error {
	identityObservationMu.Lock()
	defer identityObservationMu.Unlock()
	var fs unix.Statfs_t
	if ctx == nil || os.Getuid() != 0 || os.Geteuid() != 0 || unix.Statfs("/tmp", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return ErrInvalid
	}
	if len(retainedIdentityObservers) != 0 {
		return ErrReview
	}
	for _, scenario := range []string{"valid", "missing-registry", "empty-smb", "pending-registry", "pending-native", "pending-smb", "restored", "malformed"} {
		if err := exerciseIdentityObservationCase(ctx, scenario); err != nil {
			return fmt.Errorf("identity observation case=%s: %w", scenario, err)
		}
	}
	fmt.Println("PHANTOWD_IDENTITY_STATE_FS_READY cases=8 original_locks=true complete_roster=true pending_metadata_only=true restored_refused=true readonly=true recovery=false admission=false scope=temporary-qemu-only")
	return ctx.Err()
}

func exerciseIdentityObservationCase(ctx context.Context, scenario string) (result error) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrIO
	}
	root, err := os.MkdirTemp("/tmp", "phantowd-identity-observation-")
	if err != nil {
		return ErrIO
	}
	dirs := []string{"", "registry", "operations", "operations/first", "operations/first/smb", "operations/second"}
	files := []string{"registry/service-accounts.json", "operations/first/identity-operation.json", "operations/first/smb/smb-operation.json", "operations/second/identity-operation.json"}
	pending := ""
	var a *Observer
	defer func() {
		if a != nil && (a.state.closeFailed || a.Close() != nil) {
			retainedIdentityObservers = append(retainedIdentityObservers, a)
			result = ErrReview
			return
		}
		for _, name := range append(append([]string{}, files...), "registry/original-record", pending) {
			if name == "" {
				continue
			}
			if e := os.Remove(filepath.Join(root, name)); e != nil && !errors.Is(e, os.ErrNotExist) {
				result = ErrReview
				return
			}
		}
		for i := len(dirs) - 1; i >= 0; i-- {
			if e := os.Remove(filepath.Join(root, dirs[i])); e != nil && !errors.Is(e, os.ErrNotExist) {
				result = ErrReview
				return
			}
		}
		after, e := os.ReadDir("/proc/self/fd")
		if e != nil || len(after) != len(before) {
			result = ErrReview
		}
	}()
	for _, name := range dirs[1:] {
		if os.Mkdir(filepath.Join(root, name), 0700) != nil {
			return ErrIO
		}
	}
	r, err := serviceaccounts.New(20000, 20100)
	if err != nil {
		return ErrInvalid
	}
	for _, name := range []string{"first", "second"} {
		r, err = r.Create(r.Revision, name, name, serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}})
		if err != nil {
			return ErrInvalid
		}
	}
	values := map[string]any{"registry/service-accounts.json": r}
	for i, account := range r.Accounts {
		n := identityprovision.Journal{Format: identityprovision.Format, SchemaVersion: 1, Revision: 5, RegistryRevision: uint64(i) + 2, Account: account, Phase: identityprovision.UnixConfirmed}
		values["operations/"+account.ID+"/identity-operation.json"] = n
		if i == 0 {
			values["operations/first/smb/smb-operation.json"] = smbprovision.Journal{Format: smbprovision.Format, SchemaVersion: 1, Revision: 5, NativeRevision: 5, Account: account, SID: "S-1-5-21-1-2-3-4", Phase: smbprovision.CredentialSetDisabled}
		}
	}
	tracked := append([]string{}, dirs...)
	for _, name := range files {
		if scenario == "missing-registry" && name == files[0] || scenario == "empty-smb" && name == files[2] {
			continue
		}
		wire, e := json.Marshal(values[name])
		if e != nil {
			return ErrInvalid
		}
		if scenario == "malformed" && name == files[0] {
			wire = []byte(`{}`)
		}
		if os.WriteFile(filepath.Join(root, name), wire, 0600) != nil {
			return ErrIO
		}
		tracked = append(tracked, name)
	}
	switch scenario {
	case "pending-registry":
		pending = "registry/.service-accounts.pending"
	case "pending-native":
		pending = "operations/second/.identity-operation.pending"
	case "pending-smb":
		pending = "operations/first/smb/.smb-operation.pending"
	}
	if pending != "" {
		if os.WriteFile(filepath.Join(root, pending), []byte("never read observer pending bytes"), 0600) != nil {
			return ErrIO
		}
		tracked = append(tracked, pending)
	}
	snapshot, err := readSessionFixtureSnapshot(root, tracked)
	if err != nil {
		return err
	}
	a, err = OpenIdentity(ctx, root)
	if err != nil {
		return err
	}
	if _, e := a.Observe(ctx); e != ErrInvalid {
		return ErrReview
	}
	if _, e := a.ObserveCredentials(ctx); e != ErrInvalid {
		return ErrReview
	}
	copy := *a
	if _, e := copy.ObserveIdentity(ctx); e != ErrInvalid {
		return ErrReview
	}
	reads := 0
	if pending != "" {
		a.state.readAt = func(*os.File, []byte, int64) (int, error) { reads++; return 0, ErrIO }
	}
	if scenario == "restored" {
		if os.Rename(filepath.Join(root, files[0]), filepath.Join(root, "registry/original-record")) != nil || os.WriteFile(filepath.Join(root, files[0]), []byte(`{}`), 0600) != nil {
			return ErrIO
		}
	}
	for i := 0; i < 2; i++ {
		d, e := a.ObserveIdentity(ctx)
		switch scenario {
		case "valid":
			if e != nil || d.Kind() != identityevidence.StoredLinksObserved {
				return ErrReview
			}
		case "missing-registry":
			if e != nil || d.Kind() != identityevidence.InconsistentDocuments {
				return ErrReview
			}
		case "empty-smb":
			if e != nil || d.Kind() != identityevidence.IncompleteDocuments {
				return ErrReview
			}
		default:
			if !errors.Is(e, ErrReview) || d.Kind() != "" || reads != 0 {
				return ErrReview
			}
		}
		for _, name := range dirs {
			f, e := os.Open(filepath.Join(root, name))
			if e != nil {
				return ErrIO
			}
			lockErr := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
			if f.Close() != nil || !errors.Is(lockErr, unix.EWOULDBLOCK) {
				return ErrReview
			}
		}
		data, e := json.Marshal(d)
		if !errors.Is(e, identityevidence.ErrInvalid) || len(data) != 0 {
			return ErrReview
		}
		if i == 0 && scenario == "restored" {
			if os.Remove(filepath.Join(root, files[0])) != nil || os.Rename(filepath.Join(root, "registry/original-record"), filepath.Join(root, files[0])) != nil {
				return ErrIO
			}
		}
	}
	if a.Close() != nil {
		return ErrReview
	}
	if scenario != "restored" {
		after, e := readSessionFixtureSnapshot(root, tracked)
		if e != nil || !reflect.DeepEqual(snapshot, after) {
			return ErrReview
		}
	}
	return ctx.Err()
}
