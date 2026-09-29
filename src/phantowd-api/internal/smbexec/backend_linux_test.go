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

func TestDisableWithoutSessionsUsesFixedCommandsAndVerifiesStableAbsence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	calls, statusReads := 0, 0
	commandOutput := []byte("must be discarded")
	var pinnedConfig *os.File
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, executable string, args []string, gotConfig *os.File, stdin []byte, capture bool) ([]byte, error) {
		calls++
		if gotConfig != pinnedConfig {
			t.Fatal("disable did not use the pinned Samba configuration")
		}
		switch executable {
		case smbpasswdPath:
			if !slices.Equal(args, []string{"-d", "-c", configArgument, account.Name}) || len(stdin) != 0 || capture {
				t.Fatal("disable escaped the fixed, credential-free passdb command contract")
			}
			return commandOutput, nil
		case smbstatusPath:
			statusReads++
			if !slices.Equal(args, []string{"-j", "-s", configArgument}) || len(stdin) != 0 || !capture {
				t.Fatal("empty-session verification escaped the fixed read-only command contract")
			}
			return testSMBStatusJSON(false), nil
		default:
			t.Fatalf("unexpected command when no target session exists: %s", executable)
			return nil, ErrUnavailable
		}
	}))
	if err != nil {
		t.Fatal("secure Samba backend configuration refused", err)
	}
	pinnedConfig = backend.config
	if err := backend.Disable(context.Background(), account); err != nil || calls != 3 || statusReads != 2 {
		t.Fatalf("disable calls=%d status reads=%d error=%v", calls, statusReads, err)
	}
	if !bytes.Equal(commandOutput, make([]byte, len(commandOutput))) {
		t.Fatal("discarded command output was not cleared")
	}
}

func TestDisableRevokesOnlyTheTargetUsersSessionsAndVerifiesAbsence(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	config := secureConfig(t)
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	var pinnedConfig *os.File
	statusReads := 0
	commandNames := make([]string, 0, 5)
	backend, err := testBackend(t, config, runnerFunc(func(_ context.Context, executable string, args []string, gotConfig *os.File, stdin []byte, capture bool) ([]byte, error) {
		commandNames = append(commandNames, filepath.Base(executable))
		if gotConfig != pinnedConfig {
			t.Fatal("session revocation did not use the pinned Samba configuration")
		}
		switch executable {
		case smbpasswdPath:
			if !slices.Equal(args, []string{"-d", "-c", configArgument, account.Name}) || len(stdin) != 0 || capture {
				t.Fatal("disable escaped the fixed passdb command contract")
			}
			return []byte("discarded passdb output"), nil
		case smbstatusPath:
			if !slices.Equal(args, []string{"-j", "-s", configArgument}) || len(stdin) != 0 || !capture {
				t.Fatal("session inventory escaped the fixed read-only command contract")
			}
			statusReads++
			if statusReads == 1 {
				return testSMBStatusJSON(true), nil
			}
			return testSMBStatusJSON(false), nil
		case smbcontrolPath:
			if !slices.Equal(args, []string{"-s", configArgument, "smbd", "logoff-user", account.Name}) || len(stdin) != 0 || capture {
				t.Fatal("session revocation escaped the fixed per-user control command")
			}
			return []byte("discarded control output"), nil
		default:
			t.Fatalf("unexpected Samba executable: %s", executable)
			return nil, ErrUnavailable
		}
	}))
	if err != nil {
		t.Fatal("secure Samba backend configuration refused", err)
	}
	pinnedConfig = backend.config
	if err := backend.Disable(context.Background(), account); err != nil {
		t.Fatal("disable did not confirm revocation of the exact account's sessions", err)
	}
	if !slices.Equal(commandNames, []string{"smbpasswd", "smbstatus", "smbcontrol", "smbstatus", "smbstatus"}) || statusReads != 3 {
		t.Fatalf("disable command sequence = %v, status reads = %d", commandNames, statusReads)
	}
}

func testSMBStatusJSON(includeAlice bool) []byte {
	alice := ""
	if includeAlice {
		alice = `,"1000000000001":{"session_id":"1000000000001","username":"alice","server_id":{"pid":"1001","task_id":"0","vnn":"4294967295","unique_id":"123456789"}}`
	}
	return []byte(`{"version":"4.22.11","sessions":{"1000000000002":{"session_id":"1000000000002","username":"bob","server_id":{"pid":"1002","task_id":"0","vnn":"4294967295","unique_id":"987654321"}}` + alice + `}}`)
}

func TestDisableRefusesUnverifiableSessionInventoryBeforeControlDispatch(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	calls := 0
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, _ []string, _ *os.File, _ []byte, _ bool) ([]byte, error) {
		calls++
		if executable == smbstatusPath {
			return []byte(`{"sessions":null}`), nil
		}
		if executable == smbpasswdPath {
			return nil, nil
		}
		t.Fatalf("unverified SMB inventory must not dispatch another command: %s", executable)
		return nil, ErrUnavailable
	}))
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Disable(context.Background(), account); err != ErrUnavailable || calls != 2 {
		t.Fatalf("unverifiable active-session inventory did not fail closed: calls=%d error=%v", calls, err)
	}
}

func TestDisableNeverRepeatsSessionControlAfterUncertainVerification(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	account := serviceaccounts.Account{ID: "first", Name: "alice", UID: 11001, GID: 11001, State: serviceaccounts.Disabled}
	var pinnedConfig *os.File
	commandNames := make([]string, 0, 4)
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, _ []string, config *os.File, _ []byte, _ bool) ([]byte, error) {
		commandNames = append(commandNames, filepath.Base(executable))
		if config != pinnedConfig {
			t.Fatal("disable did not use the pinned Samba configuration")
		}
		switch executable {
		case smbpasswdPath:
			return nil, nil
		case smbstatusPath:
			if len(commandNames) == 2 {
				return testSMBStatusJSON(true), nil
			}
			return []byte(`{"sessions":null}`), nil
		case smbcontrolPath:
			return nil, nil
		default:
			t.Fatalf("unexpected Samba executable: %s", executable)
			return nil, ErrUnavailable
		}
	}))
	if err != nil {
		t.Fatal(err)
	}
	pinnedConfig = backend.config
	if err := backend.Disable(context.Background(), account); err != ErrUnavailable {
		t.Fatalf("uncertain post-control inventory was not rejected: %v", err)
	}
	if !slices.Equal(commandNames, []string{"smbpasswd", "smbstatus", "smbcontrol", "smbstatus"}) {
		t.Fatalf("uncertain revocation was retried or dispatched out of order: %v", commandNames)
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
