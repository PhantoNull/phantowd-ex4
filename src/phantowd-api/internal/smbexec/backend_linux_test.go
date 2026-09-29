//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
)

type runnerFunc func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error)

func (run runnerFunc) Run(ctx context.Context, executable string, args []string, config *os.File, stdin []byte, capture bool) ([]byte, error) {
	return run(ctx, executable, args, config, stdin, capture)
}

func testBackend(t *testing.T, configPath string, runner commandRunner) (*Backend, error) {
	t.Helper()
	backend, err := newBackend(configPath, runner)
	if err == nil {
		t.Cleanup(func() {
			if err := backend.Close(); err != nil {
				t.Error("close pinned Samba test config:", err)
			}
		})
	}
	return backend, err
}

func secureConfig(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "smb.conf")
	if err := os.WriteFile(path, []byte("[global]\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestObserveReturnsOnlyTheExactRequestedPassdbIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	fixture := []byte("Unix username: bob\nUser SID: S-1-5-21-1-2-3-1001\nAccount Flags: [U          ]\n\n" +
		"Unix username: alice\nUser SID: S-1-5-21-1-2-3-1002\nAccount Flags: [UD         ]\n")
	calls := 0
	var pinnedConfig *os.File
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, executable string, args []string, gotConfig *os.File, stdin []byte, capture bool) ([]byte, error) {
		calls++
		if executable != pdbeditPath || gotConfig != pinnedConfig || !slices.Equal(args, []string{"-L", "-v", "-s", configArgument}) || len(stdin) != 0 || !capture {
			t.Fatal("passdb observation escaped its fixed read-only command contract")
		}
		return slices.Clone(fixture), nil
	}))
	if err != nil {
		t.Fatal("secure Samba backend configuration refused", err)
	}
	pinnedConfig = backend.config
	got, err := backend.Observe(context.Background(), account)
	want := smbprovision.Observation{Present: true, Name: account.Name, UID: account.UID, GID: account.GID,
		SID: "S-1-5-21-1-2-3-1002", Disabled: true}
	if err != nil || got != want || calls != 1 {
		t.Fatalf("exact disabled account observation = %#v, calls %d, error %v", got, calls, err)
	}
}

func TestBackendKeepsTheConfigurationFileOpenedAtConstruction(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	originalInfo, err := os.Stat(config)
	if err != nil {
		t.Fatal(err)
	}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, _ string, _ []string, pinned *os.File, _ []byte, _ bool) ([]byte, error) {
		pinnedInfo, err := pinned.Stat()
		if err != nil || !os.SameFile(originalInfo, pinnedInfo) {
			t.Fatal("backend no longer references the configuration inode opened at construction")
		}
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(config, config+".replaced"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config, []byte("[global]\nsecurity = user\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := backend.Observe(context.Background(), account); err != nil {
		t.Fatal("path replacement changed the backend's pinned config", err)
	}
}

func TestCloseIsIdempotentAndDisablesFurtherCommands(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	calls := 0
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
		return nil, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal("first close:", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal("second close:", err)
	}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	if _, err := backend.Observe(context.Background(), account); err != ErrInvalid || calls != 0 {
		t.Fatalf("closed backend performed a command: calls=%d error=%v", calls, err)
	}
}

func TestNewRejectsWritableAndSymlinkedConfig(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	if err := os.Chmod(config, 0660); err != nil {
		t.Fatal(err)
	}
	if _, err := New(config); err == nil {
		t.Fatal("group-writable Samba config was accepted")
	}
	if err := os.Chmod(config, 0600); err != nil {
		t.Fatal(err)
	}
	symlink := config + ".symlink"
	if err := os.Symlink(config, symlink); err != nil {
		t.Fatal(err)
	}
	if _, err := New(symlink); err == nil {
		t.Fatal("symlinked Samba config was accepted")
	}
}

func TestNewRejectsMissingConfigWithoutCreatingAnything(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	directory := t.TempDir()
	config := filepath.Join(directory, "missing.conf")
	if backend, err := New(config); err == nil || backend != nil {
		if backend != nil {
			_ = backend.Close()
		}
		t.Fatal("missing trusted Samba config was accepted")
	}
	if _, err := os.Stat(config); !os.IsNotExist(err) {
		t.Fatalf("opening missing config created or changed the path: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil || len(entries) != 0 {
		t.Fatalf("missing config rejection left filesystem side effects: entries=%v error=%v", entries, err)
	}
}

func TestObserveTreatsMissingTargetAsExactAbsence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		return []byte("Unix username: bob\nUser SID: S-1-5-21-1-2-3-1001\nAccount Flags: [U          ]\n"), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := backend.Observe(context.Background(), account); err != nil || got != (smbprovision.Observation{}) {
		t.Fatalf("absent target = %#v, error %v", got, err)
	}
}

func TestObserveRejectsAmbiguousAndMalformedTarget(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	fixtures := map[string]string{
		"duplicate target": "Unix username: alice\nUser SID: S-1-5-21-1-2-3-1002\nAccount Flags: [UD]\n" +
			"Unix username: alice\nUser SID: S-1-5-21-1-2-3-1003\nAccount Flags: [UD]\n",
		"missing SID":              "Unix username: alice\nAccount Flags: [UD]\n",
		"malformed SID":            "Unix username: alice\nUser SID: S-1-5-21-1-2-3-0\nAccount Flags: [UD]\n",
		"malformed flags":          "Unix username: alice\nUser SID: S-1-5-21-1-2-3-1002\nAccount Flags: disabled\n",
		"missing normal-user flag": "Unix username: alice\nUser SID: S-1-5-21-1-2-3-1002\nAccount Flags: [D]\n",
	}
	for name, fixture := range fixtures {
		t.Run(name, func(t *testing.T) {
			backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, _ string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
				return []byte(fixture), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			if got, err := backend.Observe(context.Background(), account); err == nil || got != (smbprovision.Observation{}) {
				t.Fatalf("malformed or ambiguous target = %#v, error %v", got, err)
			}
		})
	}
}

func TestCreateDisabledUsesFixedCommandAndNoPasswordInput(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	calls := 0
	commandOutput := []byte("must be discarded")
	var pinnedConfig *os.File
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, executable string, args []string, gotConfig *os.File, stdin []byte, capture bool) ([]byte, error) {
		calls++
		if executable != smbpasswdPath || gotConfig != pinnedConfig ||
			!slices.Equal(args, []string{"-a", "-d", "-c", configArgument, account.Name}) || len(stdin) != 0 || capture {
			t.Fatal("disabled account creation escaped the fixed no-password contract")
		}
		return commandOutput, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	pinnedConfig = backend.config
	if err := backend.CreateDisabled(context.Background(), account); err != nil || calls != 1 {
		t.Fatalf("create disabled calls=%d error=%v", calls, err)
	}
	if !bytes.Equal(commandOutput, make([]byte, len(commandOutput))) {
		t.Fatal("discarded command output was not cleared")
	}
}

func TestSetPasswordDisabledUsesStdinAndNeverSecretArguments(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	secret := []byte("a-private-test-password")
	wantInput := append(append(append([]byte{}, secret...), '\n'), append(append([]byte{}, secret...), '\n')...)
	calls := 0
	commandOutput := []byte("must be discarded")
	var pinnedConfig *os.File
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, executable string, args []string, gotConfig *os.File, stdin []byte, capture bool) ([]byte, error) {
		calls++
		if executable != smbpasswdPath || gotConfig != pinnedConfig ||
			!slices.Equal(args, []string{"-s", "--set-password-disabled", "-c", configArgument, account.Name}) ||
			!bytes.Equal(stdin, wantInput) || capture || strings.Contains(strings.Join(args, " "), string(secret)) {
			t.Fatal("password update escaped stdin-only disabled-account contract")
		}
		return commandOutput, nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	pinnedConfig = backend.config
	if err := backend.SetPasswordDisabled(context.Background(), account, secret); err != nil || calls != 1 {
		t.Fatalf("password update calls=%d error=%v", calls, err)
	}
	if !bytes.Equal(secret, []byte("a-private-test-password")) {
		t.Fatal("backend unexpectedly modified caller-owned secret")
	}
	if !bytes.Equal(commandOutput, make([]byte, len(commandOutput))) {
		t.Fatal("discarded command output was not cleared")
	}
	clear(wantInput)
}

func TestEnableUsesOnlyTheFixedExplicitCommand(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	calls := 0
	commandOutput := []byte("must be discarded")
	var pinnedConfig *os.File
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, executable string, args []string, gotConfig *os.File, stdin []byte, capture bool) ([]byte, error) {
		calls++
		if executable != smbpasswdPath || gotConfig != pinnedConfig ||
			!slices.Equal(args, []string{"-e", "-c", configArgument, account.Name}) || len(stdin) != 0 || capture {
			t.Fatal("explicit enable escaped the fixed, credential-free command contract")
		}
		return commandOutput, nil
	}))
	if err != nil {
		t.Fatal("secure Samba backend configuration refused", err)
	}
	pinnedConfig = backend.config
	if err := backend.Enable(context.Background(), account); err != nil || calls != 1 {
		t.Fatalf("explicit enable calls=%d error=%v", calls, err)
	}
	if !bytes.Equal(commandOutput, make([]byte, len(commandOutput))) {
		t.Fatal("discarded command output was not cleared")
	}
}

func TestDisableUsesOnlyTheFixedExplicitCommand(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	calls := 0
	commandOutput := []byte("must be discarded")
	var pinnedConfig *os.File
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, executable string, args []string, gotConfig *os.File, stdin []byte, capture bool) ([]byte, error) {
		calls++
		if executable != smbpasswdPath || gotConfig != pinnedConfig ||
			!slices.Equal(args, []string{"-d", "-c", configArgument, account.Name}) || len(stdin) != 0 || capture {
			t.Fatal("disable escaped the fixed, credential-free command contract")
		}
		return commandOutput, nil
	}))
	if err != nil {
		t.Fatal("secure Samba backend configuration refused", err)
	}
	pinnedConfig = backend.config
	if err := backend.Disable(context.Background(), account); err != nil || calls != 1 {
		t.Fatalf("disable calls=%d error=%v", calls, err)
	}
	if !bytes.Equal(commandOutput, make([]byte, len(commandOutput))) {
		t.Fatal("discarded command output was not cleared")
	}
}

func TestCommandFailureDoesNotExposeDiagnostics(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		return []byte("password=should-never-escape"), ErrUnavailable
	}))
	if err != nil {
		t.Fatal(err)
	}
	got, err := backend.Observe(context.Background(), account)
	if err != ErrUnavailable || got != (smbprovision.Observation{}) || strings.Contains(err.Error(), "should-never-escape") {
		t.Fatalf("command diagnostic escaped: observation=%#v error=%v", got, err)
	}
}
