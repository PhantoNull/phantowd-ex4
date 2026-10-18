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
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var credentialObservationMu sync.Mutex
var retainedCredentialObservers []*Observer

// Public synthetic document vectors only. No enrollment, KDF, authentication,
// consumer, CHAP sink or real secret is used. All files are NEW tmpfs fixtures.
func exerciseCredentialObservationQEMU(ctx context.Context) error {
	credentialObservationMu.Lock()
	defer credentialObservationMu.Unlock()
	var fs unix.Statfs_t
	if len(retainedCredentialObservers) != 0 {
		return ErrReview
	}
	if ctx == nil || os.Geteuid() != 0 || unix.Statfs("/tmp", &fs) != nil || fs.Type != unix.TMPFS_MAGIC {
		return ErrInvalid
	}
	for _, profile := range []credentialProfile{administratorProfile, chapProfile} {
		for _, scenario := range []string{"valid", "missing", "pending", "restored", "malformed"} {
			if err := exerciseCredentialObservationCase(ctx, profile, scenario); err != nil {
				return fmt.Errorf("credential observation profile=%d case=%s: %w", profile, scenario, err)
			}
		}
	}
	fmt.Println("PHANTOWD_CREDENTIAL_STATE_FS_READY profiles=2 scenarios=10 root_only_chap=true values_redacted=true legacy_preserved=true pending_metadata_only=true original_lock=true readonly=true admission=false scope=temporary-qemu-only")
	return ctx.Err()
}

func exerciseCredentialObservationCase(ctx context.Context, profile credentialProfile, scenario string) (result error) {
	before, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return ErrIO
	}
	root, err := os.MkdirTemp("/tmp", "phantowd-credential-observation-")
	if err != nil {
		return ErrIO
	}
	spec, pending := (&state{credentials: profile}).credentialSpec()
	var a *Observer
	defer func() {
		if a != nil && (a.state.closeFailed || a.Close() != nil) {
			retainedCredentialObservers = append(retainedCredentialObservers, a)
			result = ErrReview
			return
		}
		for _, name := range []string{spec.name, pending, "original-document"} {
			if e := os.Remove(filepath.Join(root, name)); e != nil && !errors.Is(e, os.ErrNotExist) {
				result = ErrReview
				return
			}
		}
		if os.Remove(root) != nil {
			result = ErrReview
			return
		}
		after, e := os.ReadDir("/proc/self/fd")
		if e != nil || len(after) != len(before) {
			result = ErrReview
		}
	}()
	const verifier = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
	wire := []byte(`{"version":1,"admin":{"username":"public-fixture-admin","password_hash":"` + verifier + `"}}`)
	if profile == chapProfile {
		wire = []byte(`{"format":"phantowd-chap-credentials","schema_version":1,"revision":3,"entries":[{"ref":"public-fixture-ref","secret":"PublicSyntheticToken1!"}]}`)
	}
	if scenario == "malformed" {
		wire = []byte(`{}`)
	}
	if scenario != "missing" && os.WriteFile(filepath.Join(root, spec.name), wire, 0600) != nil {
		return ErrIO
	}
	if scenario == "pending" && os.WriteFile(filepath.Join(root, pending), []byte("never read staged bytes"), 0600) != nil {
		return ErrIO
	}
	tracked := []string{""}
	if scenario != "missing" {
		tracked = append(tracked, spec.name)
	}
	snapshot, err := readSessionFixtureSnapshot(root, tracked)
	if err != nil {
		return err
	}
	if profile == administratorProfile {
		a, err = OpenAdministratorCredentials(ctx, root)
	} else {
		a, err = OpenCHAPCredentials(ctx, root)
	}
	if err != nil {
		return err
	}
	if d, e := a.Observe(ctx); e != ErrInvalid || d.Kind() != "" {
		return ErrReview
	}
	if d, e := a.ObserveSession(ctx); e != ErrInvalid || d.Kind() != "" {
		return ErrReview
	}
	copyObserver := *a
	if d, e := copyObserver.ObserveCredentials(ctx); e != ErrInvalid || d.Kind() != "" {
		return ErrReview
	}
	reads := 0
	if scenario == "pending" {
		a.state.readAt = func(*os.File, []byte, int64) (int, error) { reads++; return 0, ErrIO }
	}
	if scenario == "restored" {
		if os.Rename(filepath.Join(root, spec.name), filepath.Join(root, "original-document")) != nil || os.WriteFile(filepath.Join(root, spec.name), wire, 0600) != nil {
			return ErrIO
		}
	}
	for i := 0; i < 2; i++ {
		d, e := a.ObserveCredentials(ctx)
		switch scenario {
		case "valid":
			want := uint64(1)
			if profile == chapProfile {
				want = 3
			}
			if e != nil || d.Kind() != ValidCredentialDocument || d.Revision() != want {
				return ErrReview
			}
		case "missing":
			if e != nil || d.Kind() != MissingCredentialDocument || d.Revision() != 0 {
				return ErrReview
			}
		default:
			if !errors.Is(e, ErrReview) || d != (CredentialDiagnosis{}) {
				return ErrReview
			}
		}
		if data, e := json.Marshal(d); !errors.Is(e, ErrInvalid) || len(data) != 0 {
			return ErrReview
		}
		formatted := fmt.Sprintf("%+v %#v", d, d)
		for _, private := range []string{verifier, "public-fixture-admin", "public-fixture-ref", "PublicSyntheticToken1!"} {
			if strings.Contains(formatted, private) {
				return ErrReview
			}
		}
		if reads != 0 {
			return ErrReview
		}
		probe, e := os.Open(root)
		if e != nil {
			return ErrIO
		}
		lockErr := unix.Flock(int(probe.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if probe.Close() != nil || !errors.Is(lockErr, unix.EWOULDBLOCK) {
			return ErrReview
		}
		if i == 0 && scenario == "restored" {
			if os.Remove(filepath.Join(root, spec.name)) != nil || os.Rename(filepath.Join(root, "original-document"), filepath.Join(root, spec.name)) != nil {
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
