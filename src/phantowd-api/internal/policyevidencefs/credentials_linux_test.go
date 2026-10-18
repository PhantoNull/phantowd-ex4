//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

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
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

// Existing public all-zero verifier vector. No KDF, authentication or real
// credential is involved; these inputs only test document classification.
const syntheticAdminVerifier = "$argon2id$v=19$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

func credentialFixtureDocument(profile credentialProfile, legacy bool) []byte {
	if profile == chapProfile {
		return []byte(`{"format":"phantowd-chap-credentials","schema_version":1,"revision":7,"entries":[{"ref":"synthetic-ref","secret":"PublicSyntheticValue1!"}]}`)
	}
	if legacy {
		return []byte(`{"version":1,"admin":{"username":"synthetic-admin","password_hash":"` + syntheticAdminVerifier + `"}}`)
	}
	return []byte(`{"version":2,"revision":7,"admin":{"username":"synthetic-admin","password_hash":"` + syntheticAdminVerifier + `"}}`)
}

func TestCredentialMetadataFixedSchemasAndPrivacy(t *testing.T) {
	for _, profile := range []credentialProfile{administratorProfile, chapProfile} {
		s := &state{credentials: profile}
		spec, pending := s.credentialSpec()
		if len(s.directoryObjects()) != 1 || len(s.fileObjects()) != 1 || len(s.roleSpecs()) != 1 || spec.parent != 0 || pending == "" {
			t.Fatal("incomplete fixed role")
		}
		for _, legacy := range []bool{false, true} {
			wire := credentialFixtureDocument(profile, legacy)
			before := bytes.Clone(wire)
			d, err := s.matchCredentials([]policyevidence.Slot{{State: policyevidence.Present, Data: wire}})
			want := uint64(7)
			if profile == administratorProfile && legacy {
				want = 1
			}
			if err != nil || d.Kind() != ValidCredentialDocument || d.Revision() != want || !bytes.Equal(wire, before) {
				t.Fatal("metadata classification", err)
			}
			for _, value := range []any{d, &d} {
				if data, err := json.Marshal(value); !errors.Is(err, ErrInvalid) || len(data) != 0 {
					t.Fatal("private metadata serialized")
				}
				out := fmt.Sprintf("%+v %#v", value, value)
				for _, private := range []string{"synthetic-admin", syntheticAdminVerifier, "synthetic-ref", "PublicSyntheticValue1!"} {
					if strings.Contains(out, private) {
						t.Fatal("private material formatted")
					}
				}
			}
		}
		d, err := s.matchCredentials([]policyevidence.Slot{{State: policyevidence.Absent}})
		if err != nil || d.Kind() != MissingCredentialDocument || d.Revision() != 0 {
			t.Fatal("absence fabricated valid credentials")
		}
		wire := bytes.Replace(credentialFixtureDocument(profile, false), []byte(`"revision":7`), []byte(`"revision":18446744073709551615`), 1)
		if d, err := s.matchCredentials([]policyevidence.Slot{{State: policyevidence.Present, Data: wire}}); err != nil || d.Revision() != math.MaxUint64 {
			t.Fatal("exact uint64 revision lost")
		}
		for _, slot := range []policyevidence.Slot{{}, {State: 255}, {State: policyevidence.Present}, {State: policyevidence.Present, Data: []byte(`{}`)}} {
			if d, err := s.matchCredentials([]policyevidence.Slot{slot}); err != ErrInvalid || d != (CredentialDiagnosis{}) {
				t.Fatal("invalid input returned partial metadata")
			}
		}
	}
	if d, err := (&state{}).matchCredentials([]policyevidence.Slot{{State: policyevidence.Absent}}); err != ErrInvalid || d != (CredentialDiagnosis{}) {
		t.Fatal("unselected profile admitted metadata")
	}
}

func TestCredentialObserverLifetime(t *testing.T) {
	root := t.TempDir()
	if os.Chmod(root, 0700) != nil {
		t.Fatal("root mode")
	}
	wire := credentialFixtureDocument(administratorProfile, true)
	if os.WriteFile(filepath.Join(root, "accounts.json"), wire, 0600) != nil {
		t.Fatal("fixture")
	}
	a, err := OpenAdministratorCredentials(context.Background(), root)
	if errors.Is(err, ErrUnsupported) && a == nil {
		t.Skip("unique mount ID unavailable; no positive credential lifetime")
	}
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if a.Close() != nil {
			t.Error("close")
		}
	}()
	if _, err := a.Observe(context.Background()); err != ErrInvalid {
		t.Fatal("wrong profile admitted")
	}
	if _, err := a.ObserveSession(context.Background()); err != ErrInvalid {
		t.Fatal("wrong session entrypoint admitted")
	}
	for range 2 {
		if d, err := a.ObserveCredentials(context.Background()); err != nil || d.Kind() != ValidCredentialDocument || d.Revision() != 1 {
			t.Fatal("original credential observation", err)
		}
	}
	if data, err := os.ReadFile(filepath.Join(root, "accounts.json")); err != nil || !bytes.Equal(data, wire) {
		t.Fatal("legacy account document rewritten")
	}
}

func TestCredentialConstructorRejectsMixedAndNonrootCHAPBeforeIO(t *testing.T) {
	if a, err := openNamespace(context.Background(), "/missing-credential-root", "foreign", false, nil, false, administratorProfile); a != nil || err != ErrInvalid {
		t.Fatal("mixed identity profile reached filesystem")
	}
	if a, err := openNamespace(context.Background(), "/missing-credential-root", "", false, nil, true, chapProfile); a != nil || err != ErrInvalid {
		t.Fatal("mixed session profile reached filesystem")
	}
	if a, err := OpenAdministratorCredentials(nil, "/missing-credential-root"); a != nil || err != ErrInvalid {
		t.Fatal("nil context admitted")
	}
	if os.Geteuid() != 0 {
		if a, err := OpenCHAPCredentials(context.Background(), "/missing-credential-root"); a != nil || err != ErrUnsafe {
			t.Fatal("nonroot CHAP reached filesystem")
		}
	}
	var a *Observer
	if d, err := a.ObserveCredentials(context.Background()); err != ErrInvalid || d != (CredentialDiagnosis{}) {
		t.Fatal("nil handle admitted")
	}
	var d CredentialDiagnosis
	if err := json.Unmarshal([]byte(`{}`), &d); !errors.Is(err, ErrInvalid) {
		t.Fatal("private metadata decoded")
	}
}
