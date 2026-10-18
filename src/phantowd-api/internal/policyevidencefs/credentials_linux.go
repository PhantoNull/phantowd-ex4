//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"bytes"
	"context"
	"fmt"
	"io"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/admincredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsicredentials"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
)

type credentialProfile uint8

const (
	noCredentialProfile credentialProfile = iota
	administratorProfile
	chapProfile
)

type observationMode uint8

const (
	ordinaryObservation observationMode = iota
	sessionObservation
	credentialObservation
	identityObservation
)

// Private metadata only. Neither kind grants authentication, enrollment,
// credential coverage/provenance, a session, writer ownership or boot admission.
type CredentialKind string

const (
	MissingCredentialDocument CredentialKind = "missing-credential-document"
	ValidCredentialDocument   CredentialKind = "valid-credential-document"
)

type CredentialDiagnosis struct {
	kind     CredentialKind
	revision uint64
}

func (d CredentialDiagnosis) Kind() CredentialKind       { return d.kind }
func (d CredentialDiagnosis) Revision() uint64           { return d.revision }
func (CredentialDiagnosis) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*CredentialDiagnosis) UnmarshalJSON([]byte) error  { return ErrInvalid }
func (d CredentialDiagnosis) Format(s fmt.State, _ rune) {
	_, _ = io.WriteString(s, "credential-observation{"+string(d.kind)+"}")
}

// Explicit original-directory observation of the existing dedicated account
// role, NOT admincredentials.Open (which establishes a synchronization boundary).
// No initialization, password/KDF work, session grant, migration or recovery.
func OpenAdministratorCredentials(ctx context.Context, directory string) (*Observer, error) {
	return openNamespace(ctx, directory, "", false, nil, false, administratorProfile)
}

// Preserves the vault's root-only access rule. No Owner, credential consumer,
// secret-return interface, synchronization or provisioning is constructed.
func OpenCHAPCredentials(ctx context.Context, directory string) (*Observer, error) {
	return openNamespace(ctx, directory, "", false, nil, false, chapProfile)
}

func (s *state) credentialSpec() (roleSpec, string) {
	if s.credentials == administratorProfile {
		return roleSpec{0, "accounts.json", admincredentials.MaxBytes}, ".accounts.pending"
	}
	return roleSpec{0, "chap-secrets.json", iscsicredentials.MaxObservedDocumentBytes}, ".chap-secrets.pending"
}
func (s *state) observationMode() observationMode {
	if s.identities != nil {
		return identityObservation
	}
	if s.credentials != noCredentialProfile {
		return credentialObservation
	}
	if s.sessionProfile {
		return sessionObservation
	}
	return ordinaryObservation
}
func (s *state) matchCredentials(slots []policyevidence.Slot) (CredentialDiagnosis, error) {
	if s.credentials != administratorProfile && s.credentials != chapProfile {
		return CredentialDiagnosis{}, ErrInvalid
	}
	if len(slots) != 1 {
		return CredentialDiagnosis{}, ErrInvalid
	}
	if slots[0].State == policyevidence.Absent && len(slots[0].Data) == 0 {
		return CredentialDiagnosis{kind: MissingCredentialDocument}, nil
	}
	if slots[0].State != policyevidence.Present || len(slots[0].Data) == 0 {
		return CredentialDiagnosis{}, ErrInvalid
	}
	var revision uint64
	if s.credentials == administratorProfile {
		d, err := admincredentials.Decode(bytes.NewReader(slots[0].Data))
		if err != nil {
			return CredentialDiagnosis{}, ErrInvalid
		}
		revision = d.Revision
	} else if s.credentials == chapProfile {
		var err error
		revision, err = iscsicredentials.InspectDocumentRevision(slots[0].Data)
		if err != nil {
			return CredentialDiagnosis{}, ErrInvalid
		}
	} else {
		return CredentialDiagnosis{}, ErrInvalid
	}
	return CredentialDiagnosis{ValidCredentialDocument, revision}, nil
}

// ObserveCredentials cannot be used on policy/history profiles. It reads all
// bounded original bytes under the original lock and returns metadata only.
func (a *Observer) ObserveCredentials(ctx context.Context) (CredentialDiagnosis, error) {
	d, err := a.observe(ctx, credentialObservation)
	return d.credentials, err
}
