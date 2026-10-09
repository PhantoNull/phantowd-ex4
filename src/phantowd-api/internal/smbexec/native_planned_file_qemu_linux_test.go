//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// Synthetic command-boundary input matching the pinned 4.22.11 producer,
// not a real open-file/retained-disk qualification. share_file_id is a STRING
// in that producer, unlike the numeric example in the current manual.
func testPlannedOpenFileJSONQEMU() string {
	return `{"version":"4.22.11","sessions":{"1000000000002":{"session_id":"1000000000002","username":"qpsecond","uid":2001,"gid":2001,"server_id":{"pid":"1002","task_id":"0","vnn":"4294967295","unique_id":"987654321"}}},"tcons":{"21":{"service":"writable","session_id":"1000000000002","tcon_id":"21","server_id":{"pid":"1002","task_id":"0","vnn":"4294967295","unique_id":"987654321"}}},"open_files":{"/shares/writable/created":{"service_path":"/shares/writable","filename":"created","fileid":{"devid":8,"inode":123456,"extid":0},"num_pending_deletes":0,"opens":{"1002/42":{"server_id":{"pid":"1002","task_id":"0","vnn":"4294967295","unique_id":"987654321"},"uid":2001,"share_file_id":"42","access_mask":{"hex":"0x00000003","READ_DATA":true,"WRITE_DATA":true}}}}}}`
}

func TestNativePlannedFileRequiresSameObservedSessionAndOpenGeneration(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := testPlannedOpenFileJSONQEMU()
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(_ context.Context, executable string, args []string, _ *os.File, input []byte, capture bool) ([]byte, error) {
		if executable != smbstatusPath || len(args) != 3 || args[0] != "-j" || args[1] != "-s" || args[2] != configArgument || len(input) != 0 || !capture {
			t.Fatal("file observation escaped fixed read-only status")
		}
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	original, err := native.ObservePlannedOpenFileQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); err != nil {
		t.Fatal("same observed open refused:", err)
	}
	fixture = strings.ReplaceAll(fixture, "987654321", "987654322")
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
		t.Fatal("replacement server generation became original open continuity:", err)
	}
	if _, err := json.Marshal(original); err == nil || json.Unmarshal([]byte(`{}`), &original) == nil {
		t.Fatal("private file observation crossed serialization boundary")
	}
}

func TestNativePlannedFileDistinguishesObservedClosureFromIncompleteInventory(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := testPlannedOpenFileJSONQEMU()
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	original, err := native.ObservePlannedOpenFileQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal([]byte(fixture), &root); err != nil {
		t.Fatal(err)
	}
	root["open_files"] = json.RawMessage(`{}`)
	closed, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture = string(closed)
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
		t.Fatal("complete empty file inventory was not an observed closure:", err)
	}
	if observed, err := native.ObservePlannedOpenFileQEMU(context.Background()); observed != (NativePlannedOpenFileQEMU{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("closed file became a new positive observation:", err)
	}
	root["open_files"] = json.RawMessage(`null`)
	incomplete, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	fixture = string(incomplete)
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
		t.Fatal("incomplete inventory became observed closure:", err)
	}
}

func TestNativePlannedFileRejectsCaseAliasedIdentity(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := testPlannedOpenFileJSONQEMU()
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	original, err := native.ObservePlannedOpenFileQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json accepts case aliases in structs, but these are not the
	// pinned producer's identity fields. Conflicting spellings are ambiguous.
	fixture = strings.Replace(fixture, `"uid":2001`, `"uid":0,"UID":2001`, 1)
	if observed, err := native.ObservePlannedOpenFileQEMU(context.Background()); observed != (NativePlannedOpenFileQEMU{}) || !errors.Is(err, ErrUnavailable) {
		t.Fatal("case-aliased identity became a positive observation:", err)
	}
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
		t.Fatal("ambiguous identity became continuity or an observed change:", err)
	}
}

func TestNativePlannedFileRefusesIncompleteAmbiguousOrForeignStatus(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := testPlannedOpenFileJSONQEMU()
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	original, err := native.ObservePlannedOpenFileQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct{ name, from, to string }{
		{"version", `"version":"4.22.11"`, `"version":"4.22.12"`},
		{"empty sessions", `"sessions":{`, `"sessions":{},"discarded":{`},
		{"missing trees", `"tcons":`, `"discarded":`},
		{"null files", `"open_files":{`, `"open_files":null,"discarded":{`},
		{"missing files", `"open_files":`, `"discarded":`},
		{"wrong username", `"username":"qpsecond"`, `"username":"qpmanaged"`},
		{"wrong uid", `"uid":2001`, `"uid":2000`},
		{"missing gid", `"gid":2001,`, ``},
		{"duplicate uid", `"uid":2001`, `"uid":0,"uid":2001`},
		{"aliased version", `"version":`, `"VERSION":`},
		{"aliased access", `"READ_DATA":true`, `"read_data":true`},
		{"tree key mismatch", `"tcon_id":"21"`, `"tcon_id":"22"`},
		{"foreign tree", `"service":"writable"`, `"service":"readonly"`},
		{"extra tree", `"tcons":{`, `"tcons":{"22":{},`},
		{"extra file", `"open_files":{`, `"open_files":{"/other":{},`},
		{"extra open", `"opens":{`, `"opens":{"1002/43":{},`},
		{"missing device", `"devid":8,`, ``},
		{"null device", `"devid":8`, `"devid":null`},
		{"zero inode", `"inode":123456`, `"inode":0`},
		{"overflow inode", `"inode":123456`, `"inode":18446744073709551616`},
		{"fractional inode", `"inode":123456`, `"inode":123456.5`},
		{"missing extid", `,"extid":0`, ``},
		{"unsupported extid", `"extid":0`, `"extid":1`},
		{"missing delete count", `"num_pending_deletes":0,`, ``},
		{"pending delete", `"num_pending_deletes":0`, `"num_pending_deletes":1`},
		{"numeric open id", `"share_file_id":"42"`, `"share_file_id":42`},
		{"noncanonical open id", `"share_file_id":"42"`, `"share_file_id":"042"`},
		{"zero open id", `"share_file_id":"42"`, `"share_file_id":"0"`},
		{"overflow open id", `"share_file_id":"42"`, `"share_file_id":"18446744073709551616"`},
		{"foreign open generation", `"opens":{"1002/42":{"server_id":{"pid":"1002"`, `"opens":{"1002/42":{"server_id":{"pid":"1003"`},
		{"readonly open", `"WRITE_DATA":true`, `"WRITE_DATA":false`},
		{"wrong mask", `"hex":"0x00000003"`, `"hex":"0x00000001"`},
		{"wrong filename", `"filename":"created"`, `"filename":"other"`},
		{"wrong service path", `"service_path":"/shares/writable"`, `"service_path":"/shares/readonly"`},
	} {
		t.Run(test.name, func(t *testing.T) {
			base := testPlannedOpenFileJSONQEMU()
			if !strings.Contains(base, test.from) {
				t.Fatal("negative fixture did not change its intended field")
			}
			fixture = strings.Replace(base, test.from, test.to, 1)
			if observed, err := native.ObservePlannedOpenFileQEMU(context.Background()); observed != (NativePlannedOpenFileQEMU{}) || !errors.Is(err, ErrUnavailable) {
				t.Fatal("unqualified inventory became positive:", err)
			}
			if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
				t.Fatal("unqualified inventory became continuity or observed change:", err)
			}
		})
	}
	for _, invalid := range []string{
		testPlannedOpenFileJSONQEMU() + `{}`,
		strings.Repeat(" ", maxObserveBytes+1) + testPlannedOpenFileJSONQEMU(),
		strings.Repeat("[", 17) + testPlannedOpenFileJSONQEMU() + strings.Repeat("]", 17),
	} {
		fixture = invalid
		if observed, err := native.ObservePlannedOpenFileQEMU(context.Background()); observed != (NativePlannedOpenFileQEMU{}) || !errors.Is(err, ErrUnavailable) {
			t.Fatal("status bounds/trailing-value refusal failed:", err)
		}
	}
}

func TestNativePlannedFileRejectsReplacementOfObservedOpen(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	fixture := testPlannedOpenFileJSONQEMU()
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		return []byte(fixture), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	original, err := native.ObservePlannedOpenFileQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, replacement := range []string{
		strings.ReplaceAll(fixture, "1000000000002", "1000000000003"),
		strings.ReplaceAll(fixture, `"21"`, `"22"`),
		strings.Replace(fixture, `"devid":8`, `"devid":9`, 1),
		strings.Replace(fixture, `"inode":123456`, `"inode":123457`, 1),
		strings.Replace(strings.Replace(fixture, `"1002/42"`, `"1002/43"`, 1), `"share_file_id":"42"`, `"share_file_id":"43"`, 1),
	} {
		fixture = replacement
		if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
			t.Fatal("replacement became original-open continuity:", err)
		}
	}
}

func TestNativePlannedFileRefusesCanceledFailedForeignAndClosedObservation(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("trusted Samba adapter tests require root-owned fixture config")
	}
	calls := 0
	var duringRun func()
	var runErr error
	backend, err := testBackend(t, secureConfig(t), runnerFunc(func(context.Context, string, []string, *os.File, []byte, bool) ([]byte, error) {
		calls++
		if duringRun != nil {
			duringRun()
		}
		return []byte(testPlannedOpenFileJSONQEMU()), runErr
	}))
	if err != nil {
		t.Fatal(err)
	}
	native := &NativeBackendQEMU{inner: backend}
	original, err := native.ObservePlannedOpenFileQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	calls = 0
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if observed, err := native.ObservePlannedOpenFileQEMU(ctx); observed != (NativePlannedOpenFileQEMU{}) || !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled observation became positive:", err)
	}
	if err := native.VerifyPlannedOpenFileQEMU(ctx, original); !errors.Is(err, context.Canceled) {
		t.Fatal("pre-canceled verification lost its refusal:", err)
	}
	foreign := &NativeBackendQEMU{inner: backend}
	if err := foreign.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrInvalid) {
		t.Fatal("observation from a different backend was accepted:", err)
	}
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), NativePlannedOpenFileQEMU{}); !errors.Is(err, ErrInvalid) {
		t.Fatal("empty observation was accepted:", err)
	}
	if observed, err := native.ObservePlannedOpenFileQEMU(nil); observed != (NativePlannedOpenFileQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal("nil context was accepted:", err)
	}
	if calls != 0 {
		t.Fatal("invalid/canceled observation dispatched status")
	}
	ctx, cancel = context.WithCancel(context.Background())
	duringRun = cancel
	if err := native.VerifyPlannedOpenFileQEMU(ctx, original); !errors.Is(err, context.Canceled) || !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
		t.Fatal("reply after cancellation became continuity or observed change:", err)
	}
	duringRun = nil
	runErr = errors.New("private-runner-detail-must-not-leak")
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), runErr.Error()) || errors.Is(err, ErrNativePlannedOpenFileChangedQEMU) {
		t.Fatal("runner failure became continuity/change or leaked cause:", err)
	}
	if err := backend.Close(); err != nil {
		t.Fatal(err)
	}
	calls = 0
	if observed, err := native.ObservePlannedOpenFileQEMU(context.Background()); observed != (NativePlannedOpenFileQEMU{}) || !errors.Is(err, ErrInvalid) {
		t.Fatal("closed inner admitted observation:", err)
	}
	if err := native.VerifyPlannedOpenFileQEMU(context.Background(), original); !errors.Is(err, ErrInvalid) || calls != 0 {
		t.Fatal("closed inner dispatched verification:", err)
	}
}
