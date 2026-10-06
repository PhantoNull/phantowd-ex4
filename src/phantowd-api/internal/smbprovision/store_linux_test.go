// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package tests for the internal Samba enrollment journal.
package smbprovision

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

const testSID = "S-1-5-21-1-2-3-1001"

type modeledBackend struct {
	observation  Observation
	observeErr   error
	createErr    error
	passwordErr  error
	enableErr    error
	disableErr   error
	createCalls  int
	setCalls     int
	enableCalls  int
	disableCalls int
	received     []byte
}

func (b *modeledBackend) Observe(_ context.Context, account serviceAccount) (Observation, error) {
	if b.observeErr != nil {
		return Observation{}, b.observeErr
	}
	if b.observation.Present && b.observation.Name != account.Name {
		return Observation{}, errors.New("PRIVATE observer mismatch")
	}
	return b.observation, nil
}

// serviceAccount is an alias in this test file so the fake is deliberately
// coupled to the operation's bound account, not to caller-provided identifiers.
type serviceAccount = serviceaccounts.Account

func (b *modeledBackend) CreateDisabled(_ context.Context, account serviceAccount) error {
	b.createCalls++
	if b.observation.Present {
		return errors.New("PRIVATE account already exists")
	}
	b.observation = Observation{Present: true, Name: account.Name, UID: account.UID,
		GID: account.GID, SID: testSID, Disabled: true}
	return b.createErr
}

func (b *modeledBackend) SetPasswordDisabled(_ context.Context, account serviceAccount, secret []byte) error {
	b.setCalls++
	if !b.observation.Present || !b.observation.Disabled || b.observation.Name != account.Name {
		return errors.New("PRIVATE account is not the expected disabled entry")
	}
	b.received = append([]byte{}, secret...)
	return b.passwordErr
}

func (b *modeledBackend) Enable(_ context.Context, account serviceAccount) error {
	b.enableCalls++
	if !b.observation.Present || !b.observation.Disabled || b.observation.Name != account.Name {
		return errors.New("PRIVATE account is not the expected disabled entry")
	}
	b.observation.Disabled = false
	return b.enableErr
}

func (b *modeledBackend) Disable(_ context.Context, account serviceAccount) error {
	b.disableCalls++
	if !b.observation.Present || b.observation.Disabled || b.observation.Name != account.Name {
		return errors.New("PRIVATE account is not the expected enabled entry")
	}
	b.observation.Disabled = true
	return b.disableErr
}

func privateStore(t *testing.T, backend Backend) (*Store, string) {
	t.Helper()
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := Open(directory, backend)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	return store, directory
}

func TestEnrollmentLifecycleStaysDisabledAndNeverPersistsPassword(t *testing.T) {
	ctx := context.Background()
	b := &modeledBackend{}
	s, directory := privateStore(t, b)
	if err := s.Begin(ctx, 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	j, err := s.Load()
	if err != nil || j.Phase != DisabledNoPassword || j.Revision != 3 || j.SID != testSID || !b.observation.Disabled {
		t.Fatal("new account was not durably confirmed disabled", j, err, b.observation)
	}
	if err := s.Step(ctx, 3); !errors.Is(err, ErrPending) || b.createCalls != 1 {
		t.Fatal("disabled account step retried or hid pending password work", err, b.createCalls)
	}
	secret := []byte("a-local-fixture-secret")
	if err := s.SetPasswordDisabled(ctx, 3, secret); err != nil {
		t.Fatal(err)
	}
	for i := range secret {
		secret[i] = 0
	}
	j, err = s.Load()
	if err != nil || j.Phase != CredentialSetDisabled || j.Revision != 5 || j.SID != testSID || !b.observation.Disabled {
		t.Fatal("password was not confirmed while disabled", j, err, b.observation)
	}
	if b.createCalls != 1 || b.setCalls != 1 || string(b.received) != "a-local-fixture-secret" {
		t.Fatal("unexpected backend calls or secret transport", b.createCalls, b.setCalls)
	}
	data, err := os.ReadFile(directory + "/smb-operation.json")
	if err != nil || strings.Contains(string(data), "a-local-fixture-secret") || strings.Contains(string(data), "password") || strings.Contains(string(data), "hash") {
		t.Fatal("journal contains credential material", string(data), err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, b)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if j, err := reopened.Load(); err != nil || j.Phase != CredentialSetDisabled || j.Revision != 5 {
		t.Fatal("confirmed enrollment did not survive reopen", j, err)
	}
	if err := reopened.Step(ctx, 5); err != nil || b.createCalls != 1 || b.setCalls != 1 {
		t.Fatal("completed enrollment repeated a native operation", err, b.createCalls, b.setCalls)
	}
	if err := reopened.SetPasswordDisabled(ctx, 4, []byte("another-local-fixture-secret")); !errors.Is(err, ErrConflict) {
		t.Fatal("stale credential revision accepted", err)
	}
}

func TestEnableIsExplicitRevisionCheckedAndConfirmsSameSID(t *testing.T) {
	ctx := context.Background()
	b := &modeledBackend{}
	s, _ := privateStore(t, b)
	if err := s.Begin(ctx, 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordDisabled(ctx, 3, []byte("a-local-fixture-secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(ctx, 4); !errors.Is(err, ErrConflict) || b.enableCalls != 0 {
		t.Fatal("stale enable revision was dispatched", err, b.enableCalls)
	}
	if err := s.Enable(ctx, 5); err != nil {
		t.Fatal("explicit enable failed", err)
	}
	j, err := s.Load()
	if err != nil || j.Phase != Enabled || j.Revision != 7 || j.SID != testSID || b.observation.Disabled || b.enableCalls != 1 {
		t.Fatal("enabled state was not confirmed against the same SID", j, err, b.observation, b.enableCalls)
	}
	if err := s.Enable(ctx, 5); !errors.Is(err, ErrConflict) || b.enableCalls != 1 {
		t.Fatal("confirmed enable could be repeated", err, b.enableCalls)
	}
}

func TestDisableIsExplicitRevisionCheckedAndCanBeReenabled(t *testing.T) {
	ctx := context.Background()
	b := &modeledBackend{}
	s, _ := privateStore(t, b)
	if err := s.Begin(ctx, 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordDisabled(ctx, 3, []byte("a-local-fixture-secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := s.Disable(ctx, 6); !errors.Is(err, ErrConflict) || b.disableCalls != 0 {
		t.Fatal("stale disable revision reached the backend", err, b.disableCalls)
	}
	if err := s.Disable(ctx, 7); err != nil {
		t.Fatal("explicit disable failed", err)
	}
	j, err := s.Load()
	if err != nil || j.Phase != Disabled || j.Revision != 9 || j.SID != testSID || !b.observation.Disabled || b.disableCalls != 1 {
		t.Fatal("disable was not confirmed for the same SID", j, err, b)
	}
	if err := s.Enable(ctx, 8); !errors.Is(err, ErrConflict) || b.enableCalls != 1 {
		t.Fatal("stale re-enable revision reached the backend", err, b.enableCalls)
	}
	if err := s.Enable(ctx, 9); err != nil {
		t.Fatal("explicit re-enable failed", err)
	}
	j, err = s.Load()
	if err != nil || j.Phase != Enabled || j.Revision != 11 || j.SID != testSID || b.observation.Disabled || b.enableCalls != 2 {
		t.Fatal("re-enable was not confirmed for the same SID", j, err, b)
	}
}

func TestEnableQuarantinesUnexpectedStateWithoutDispatch(t *testing.T) {
	b := &modeledBackend{}
	s, _ := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordDisabled(context.Background(), 3, []byte("a-local-fixture-secret")); err != nil {
		t.Fatal(err)
	}
	b.observation.Disabled = false // A non-cooperating writer enabled it.
	if err := s.Enable(context.Background(), 5); !errors.Is(err, ErrReview) || b.enableCalls != 0 {
		t.Fatal("unexpected enabled state was adopted or mutated", err, b.enableCalls)
	}
	j, err := s.Load()
	if err != nil || j.Phase != ReviewRequired || j.Revision != 6 || j.SID != testSID {
		t.Fatal("external state change was not quarantined", j, err)
	}
}

func TestAmbiguousDisableRequiresReviewAndNeverReplays(t *testing.T) {
	b := &modeledBackend{}
	s, _ := privateStore(t, b)
	ctx := context.Background()
	if err := s.Begin(ctx, 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordDisabled(ctx, 3, []byte("a-local-fixture-secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(ctx, 5); err != nil {
		t.Fatal(err)
	}
	b.disableErr = errors.New("PRIVATE disable reply lost after mutation")
	if err := s.Disable(ctx, 7); !errors.Is(err, ErrReview) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("uncertain disable was not converted to redacted review", err)
	}
	j, err := s.Load()
	if err != nil || j.Phase != ReviewRequired || j.Revision != 9 || j.SID != testSID || b.disableCalls != 1 {
		t.Fatal("uncertain disable evidence was not retained", j, err, b.disableCalls)
	}
	if err := s.Disable(ctx, 9); !errors.Is(err, ErrReview) || b.disableCalls != 1 {
		t.Fatal("uncertain disable was replayed", err, b.disableCalls)
	}
}

func TestAmbiguousEnableRequiresReviewAndNeverReplays(t *testing.T) {
	b := &modeledBackend{enableErr: errors.New("PRIVATE enable result uncertain")}
	s, directory := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordDisabled(context.Background(), 3, []byte("private-fixture-password")); err != nil {
		t.Fatal(err)
	}
	if err := s.Enable(context.Background(), 5); !errors.Is(err, ErrReview) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("ambiguous enable was not redacted review", err)
	}
	j, err := s.Load()
	if err != nil || j.Phase != ReviewRequired || j.Revision != 7 || j.SID != testSID || b.enableCalls != 1 {
		t.Fatal("ambiguous enable evidence was not retained", j, err, b.enableCalls)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, b)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if _, err := reopened.RecoverInterrupted(); err != nil {
		t.Fatal(err)
	}
	if err := reopened.Enable(context.Background(), 7); !errors.Is(err, ErrReview) || b.enableCalls != 1 {
		t.Fatal("ambiguous enable was retried after reopen", err, b.enableCalls)
	}
}

func TestStoreBackendIsFixedAtOpen(t *testing.T) {
	s, _ := privateStore(t, nil)
	if err := s.Begin(context.Background(), 5, testAccount); !errors.Is(err, ErrInvalid) {
		t.Fatal("read-only store opened without a bound trusted backend became mutating", err)
	}
	if j, err := s.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) || j != (Journal{}) {
		t.Fatal("backend refusal created an enrollment journal", j, err)
	}
}

func TestPreexistingPassdbEntryIsNotAdopted(t *testing.T) {
	b := &modeledBackend{observation: Observation{Present: true, Name: testAccount.Name,
		UID: testAccount.UID, GID: testAccount.GID, SID: testSID, Disabled: true}}
	s, _ := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); !errors.Is(err, ErrReview) {
		t.Fatal("pre-existing passdb account was adopted", err)
	}
	if _, err := s.Load(); !errors.Is(err, revisionstore.ErrNotInitialized) || b.createCalls != 0 || b.setCalls != 0 {
		t.Fatal("refused adoption created a journal or ran a command", err)
	}
}

func TestPassdbEntryAppearingBeforeCreateIntentIsQuarantined(t *testing.T) {
	b := &modeledBackend{}
	s, directory := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	b.observation = Observation{Present: true, Name: testAccount.Name, UID: testAccount.UID,
		GID: testAccount.GID, SID: testSID, Disabled: true}
	if err := s.Step(context.Background(), 1); !errors.Is(err, ErrReview) || b.createCalls != 0 {
		t.Fatal("a passdb entry that appeared after Begin was adopted or mutated", err, b.createCalls)
	}
	journal, err := s.Load()
	if err != nil || journal.Phase != ReviewRequired || journal.Revision != 2 {
		t.Fatal("pre-intent passdb collision was not durably quarantined", journal, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, b)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Step(context.Background(), 2); !errors.Is(err, ErrReview) || b.createCalls != 0 {
		t.Fatal("pre-intent passdb collision was retried after reopen", err, b.createCalls)
	}
}

func TestPreCommandObservationFailureLeavesReservedState(t *testing.T) {
	b := &modeledBackend{}
	s, _ := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	b.observeErr = errors.New("PRIVATE passdb details")
	if err := s.Step(context.Background(), 1); !errors.Is(err, ErrObservation) {
		t.Fatal("unavailable pre-command observation was not refused", err)
	}
	b.observeErr = nil
	if j, err := s.Load(); err != nil || j.Phase != Reserved || j.Revision != 1 || b.createCalls != 0 {
		t.Fatal("observation failure lost intent or dispatched mutation", j, err, b.createCalls)
	}
}

func TestAmbiguousCreateIsReviewAndNeverReplayed(t *testing.T) {
	b := &modeledBackend{createErr: errors.New("PRIVATE command response lost")}
	s, directory := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 1); !errors.Is(err, ErrReview) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("ambiguous command did not return redacted review", err)
	}
	if j, err := s.Load(); err != nil || j.Phase != ReviewRequired || j.Revision != 3 {
		t.Fatal("ambiguous create evidence was not retained", j, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, b)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Step(context.Background(), 3); !errors.Is(err, ErrReview) || b.createCalls != 1 {
		t.Fatal("ambiguous create was replayed after reopen", err, b.createCalls)
	}
}

func TestAmbiguousPasswordSetIsReviewAndNeverReplayed(t *testing.T) {
	b := &modeledBackend{}
	s, directory := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	b.passwordErr = errors.New("PRIVATE password result uncertain")
	if err := s.SetPasswordDisabled(context.Background(), 3, []byte("private-fixture-password")); !errors.Is(err, ErrReview) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("ambiguous password result was not redacted review", err)
	}
	if j, err := s.Load(); err != nil || j.Phase != ReviewRequired || j.Revision != 5 || j.SID != testSID {
		t.Fatal("ambiguous password evidence was not retained", j, err)
	}
	data, err := os.ReadFile(directory + "/smb-operation.json")
	if err != nil || strings.Contains(string(data), "private-fixture-password") {
		t.Fatal("ambiguous password leaked to the journal", string(data), err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(directory, b)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.SetPasswordDisabled(context.Background(), 5, []byte("private-fixture-password")); !errors.Is(err, ErrReview) || b.setCalls != 1 {
		t.Fatal("ambiguous password was replayed after reopen", err, b.setCalls)
	}
}

func TestHelperCrashAfterCreateIntent(t *testing.T) {
	directory := os.Getenv("PHANTOWD_SMBPROVISION_CRASH_DIR")
	if directory == "" {
		return
	}
	s, err := Open(directory, &exitAfterIntentBackend{})
	if err != nil {
		os.Exit(80)
	}
	if err := s.Step(context.Background(), 1); err != nil {
		os.Exit(81)
	}
	os.Exit(82)
}

type exitAfterIntentBackend struct{}

func (*exitAfterIntentBackend) Observe(context.Context, serviceaccounts.Account) (Observation, error) {
	return Observation{}, nil
}
func (*exitAfterIntentBackend) CreateDisabled(context.Context, serviceaccounts.Account) error {
	os.Exit(42)
	return nil
}
func (*exitAfterIntentBackend) SetPasswordDisabled(context.Context, serviceaccounts.Account, []byte) error {
	return errors.New("unexpected password command")
}
func (*exitAfterIntentBackend) Enable(context.Context, serviceaccounts.Account) error {
	return errors.New("unexpected enable command")
}
func (*exitAfterIntentBackend) Disable(context.Context, serviceaccounts.Account) error {
	return errors.New("unexpected disable command")
}

func TestProcessExitAfterIntentRequiresReviewWithoutReplay(t *testing.T) {
	if os.Getenv("PHANTOWD_SMBPROVISION_CRASH_DIR") != "" {
		return
	}
	backend := &modeledBackend{}
	s, directory := privateStore(t, backend)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestHelperCrashAfterCreateIntent$")
	command.Env = append(os.Environ(), "PHANTOWD_SMBPROVISION_CRASH_DIR="+directory)
	if err := command.Run(); err == nil {
		t.Fatal("child unexpectedly survived command dispatch")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 42 {
		t.Fatal("unexpected child process outcome", err)
	}
	backend = &modeledBackend{}
	reopened, err := Open(directory, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	if err := reopened.Step(context.Background(), 2); !errors.Is(err, ErrReview) || backend.createCalls != 0 {
		t.Fatal("resumed create intent was not quarantined", err, backend.createCalls)
	}
	if j, err := reopened.Load(); err != nil || j.Phase != ReviewRequired || j.Revision != 3 {
		t.Fatal("interrupted intent did not become review-required", j, err)
	}
}

func TestHelperCrashAfterPasswordIntent(t *testing.T) {
	directory := os.Getenv("PHANTOWD_SMBPROVISION_PASSWORD_CRASH_DIR")
	if directory == "" {
		return
	}
	backend := &exitAfterPasswordIntentBackend{observation: Observation{Present: true, Name: testAccount.Name,
		UID: testAccount.UID, GID: testAccount.GID, SID: testSID, Disabled: true}}
	s, err := Open(directory, backend)
	if err != nil {
		os.Exit(90)
	}
	_ = s.SetPasswordDisabled(context.Background(), 3, []byte("private-crash-fixture-secret"))
	os.Exit(91)
}

func TestHelperCrashAfterEnableIntent(t *testing.T) {
	directory := os.Getenv("PHANTOWD_SMBPROVISION_ENABLE_CRASH_DIR")
	if directory == "" {
		return
	}
	backend := &exitAfterEnableIntentBackend{observation: Observation{Present: true, Name: testAccount.Name,
		UID: testAccount.UID, GID: testAccount.GID, SID: testSID, Disabled: true}}
	s, err := Open(directory, backend)
	if err != nil {
		os.Exit(100)
	}
	_ = s.Enable(context.Background(), 5)
	os.Exit(101)
}

type exitAfterPasswordIntentBackend struct {
	observation Observation
}

func (b *exitAfterPasswordIntentBackend) Observe(context.Context, serviceaccounts.Account) (Observation, error) {
	return b.observation, nil
}
func (*exitAfterPasswordIntentBackend) CreateDisabled(context.Context, serviceaccounts.Account) error {
	return errors.New("unexpected create command")
}
func (*exitAfterPasswordIntentBackend) SetPasswordDisabled(context.Context, serviceaccounts.Account, []byte) error {
	os.Exit(43)
	return nil
}
func (*exitAfterPasswordIntentBackend) Enable(context.Context, serviceaccounts.Account) error {
	return errors.New("unexpected enable command")
}
func (*exitAfterPasswordIntentBackend) Disable(context.Context, serviceaccounts.Account) error {
	return errors.New("unexpected disable command")
}

type exitAfterEnableIntentBackend struct{ observation Observation }

func (b *exitAfterEnableIntentBackend) Observe(context.Context, serviceaccounts.Account) (Observation, error) {
	return b.observation, nil
}
func (*exitAfterEnableIntentBackend) CreateDisabled(context.Context, serviceaccounts.Account) error {
	return errors.New("unexpected create command")
}
func (*exitAfterEnableIntentBackend) SetPasswordDisabled(context.Context, serviceaccounts.Account, []byte) error {
	return errors.New("unexpected password command")
}
func (*exitAfterEnableIntentBackend) Enable(context.Context, serviceaccounts.Account) error {
	os.Exit(44)
	return nil
}
func (*exitAfterEnableIntentBackend) Disable(context.Context, serviceaccounts.Account) error {
	return errors.New("unexpected disable command")
}

func TestInterruptedPasswordIntentIsRecoveredToReviewWithoutRetry(t *testing.T) {
	backend := &modeledBackend{}
	s, directory := privateStore(t, backend)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestHelperCrashAfterPasswordIntent$")
	command.Env = append(os.Environ(), "PHANTOWD_SMBPROVISION_PASSWORD_CRASH_DIR="+directory)
	if err := command.Run(); err == nil {
		t.Fatal("child unexpectedly survived password command dispatch")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 43 {
		t.Fatal("unexpected child process outcome", err)
	}
	reopened, err := Open(directory, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	journal, err := reopened.RecoverInterrupted()
	if err != nil || journal.Phase != ReviewRequired || journal.Revision != 5 || journal.SID != testSID {
		t.Fatal("password intent was not recovered as review", journal, err)
	}
	if err := reopened.SetPasswordDisabled(context.Background(), 5, []byte("private-crash-fixture-secret")); !errors.Is(err, ErrReview) || backend.setCalls != 0 {
		t.Fatal("interrupted password command was replayed", err, backend.setCalls)
	}
	data, err := os.ReadFile(directory + "/smb-operation.json")
	if err != nil || strings.Contains(string(data), "private-crash-fixture-secret") {
		t.Fatal("interrupted password secret entered the journal", string(data), err)
	}
}

func TestInterruptedEnableIntentIsRecoveredToReviewWithoutRetry(t *testing.T) {
	backend := &modeledBackend{}
	s, directory := privateStore(t, backend)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordDisabled(context.Background(), 3, []byte("private-crash-fixture-secret")); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	command := exec.Command(os.Args[0], "-test.run=^TestHelperCrashAfterEnableIntent$")
	command.Env = append(os.Environ(), "PHANTOWD_SMBPROVISION_ENABLE_CRASH_DIR="+directory)
	if err := command.Run(); err == nil {
		t.Fatal("child unexpectedly survived enable dispatch")
	} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 44 {
		t.Fatal("unexpected enable interruption outcome", err)
	}
	reopened, err := Open(directory, backend)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	journal, err := reopened.RecoverInterrupted()
	if err != nil || journal.Phase != ReviewRequired || journal.Revision != 7 || journal.SID != testSID {
		t.Fatal("interrupted enable intent was not quarantined", journal, err)
	}
	if err := reopened.Enable(context.Background(), 7); !errors.Is(err, ErrReview) || backend.enableCalls != 0 {
		t.Fatal("interrupted enable was automatically replayed", err, backend.enableCalls)
	}
}

func TestInvalidPasswordDoesNotAdvanceJournal(t *testing.T) {
	b := &modeledBackend{}
	s, _ := privateStore(t, b)
	if err := s.Begin(context.Background(), 5, testAccount); err != nil {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	if err := s.SetPasswordDisabled(context.Background(), 3, []byte("bad\npassword")); !errors.Is(err, ErrInvalid) || b.setCalls != 0 {
		t.Fatal("invalid password was dispatched", err, b.setCalls)
	}
	if j, err := s.Load(); err != nil || j.Phase != DisabledNoPassword || j.Revision != 3 {
		t.Fatal("invalid password changed durable state", j, err)
	}
}

func ExampleStore() {
	fmt.Println("Samba enrollment: absent → disabled → credential-set-disabled")
	// Output: Samba enrollment: absent → disabled → credential-set-disabled
}
