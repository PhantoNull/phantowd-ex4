// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccountstore"
)

// Model only the external Samba teardown boundary. The Owner, stores and
// cooperative filesystem leases are real. An uncertain teardown intentionally
// retains descriptors, so run this fault in its own disposable test process.
type uncertainCloseSMB struct {
	modeledSMB
	closeCalls int
	closeErr   error
	onClose    func() error
}

func (b *uncertainCloseSMB) Close() error {
	b.closeCalls++
	if b.onClose != nil {
		return b.onClose()
	}
	return b.closeErr
}

func TestOwnerFailedOpenReportsBackendCleanupUncertainty(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(fmt.Sprint(uncertain), func(t *testing.T) {
			b := &uncertainCloseSMB{}
			if uncertain {
				b.closeErr = errors.New("PRIVATE failed-open teardown detail")
			}
			// Nil inventory fails admission before any path is opened. The
			// public constructor nevertheless owns this backend's cleanup.
			owner, err := OpenWithSMBBackend("/not-opened", nil, b)
			if owner != nil || !errors.Is(err, ErrInvalid) || b.closeCalls != 1 {
				t.Fatalf("failed admission or single cleanup changed: owner=%v err=%v calls=%d", owner, err, b.closeCalls)
			}
			if errors.Is(err, ErrReview) != uncertain || errors.Is(err, ErrUnavailable) != uncertain || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatalf("cleanup uncertainty missing or leaked: %v", err)
			}
			if !uncertain && err != ErrInvalid {
				t.Fatal("confirmed cleanup changed the original exact error", err)
			}
		})
	}
}

func TestOwnerFailedOpenRetainsAuthorityOnUncertainCleanup(t *testing.T) {
	const childVariable = "PHANTOWD_OWNER_FAILED_OPEN_FIXTURE"
	dir := os.Getenv(childVariable)
	if dir == "" {
		dir = provision(t)
		if err := os.Mkdir(dir+"/operations/orphan", 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		child := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOwnerFailedOpenRetainsAuthorityOnUncertainCleanup$", "-test.v")
		child.Env = append(os.Environ(), childVariable+"="+dir)
		output, err := child.CombinedOutput()
		if err != nil || !strings.Contains(string(output), "--- PASS: TestOwnerFailedOpenRetainsAuthorityOnUncertainCleanup") {
			t.Fatalf("failed-open child: %v\n%s", err, output)
		}
		// Only process exit releases this deliberately quarantined experiment.
		writer, err := serviceaccountstore.Open(dir + "/registry")
		if err != nil {
			t.Fatal("test process did not release registry:", err)
		}
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("failed-open fixture requires isolated root test lane")
	}
	if !filepath.IsAbs(dir) || !strings.HasPrefix(filepath.Clean(dir), filepath.Clean(os.TempDir())+string(os.PathSeparator)) ||
		!strings.HasPrefix(filepath.Base(filepath.Dir(dir)), "TestOwnerFailedOpenRetainsAuthorityOnUncertainCleanup") {
		t.Fatal("failed-open child accepts only its disposable test directory")
	}
	b := &uncertainCloseSMB{closeErr: errors.New("PRIVATE failed-open cleanup detail")}
	deps := newModel().dependencies()
	deps.smbBackend = b
	owner, err := open(dir, deps)
	if owner != nil || !errors.Is(err, ErrUnavailable) || !errors.Is(err, ErrReview) || b.closeCalls != 1 || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatalf("failed snapshot hid uncertain cleanup: owner=%v err=%v calls=%d", owner, err, b.closeCalls)
	}
	if other, err := open(dir, newModel().dependencies()); other != nil || !errors.Is(err, ErrBusy) {
		t.Fatal("failed-open quarantine lost root authority:", err)
	}
	if writer, err := serviceaccountstore.Open(dir + "/registry"); writer != nil || !errors.Is(err, revisionstore.ErrBusy) {
		t.Fatal("failed-open quarantine lost registry authority:", err)
	}
	if b.closeCalls != 1 {
		t.Fatal("failed cleanup was retried")
	}
}

func TestOwnerFailedOpenConfirmedCleanupPreservesErrorAndReleasesLocks(t *testing.T) {
	dir := provision(t)
	if err := os.Mkdir(dir+"/operations/orphan", 0700); err != nil {
		t.Fatal(err)
	}
	b := &uncertainCloseSMB{}
	deps := newModel().dependencies()
	deps.smbBackend = b
	owner, err := open(dir, deps)
	if owner != nil || err != ErrUnavailable || b.closeCalls != 1 {
		t.Fatalf("confirmed cleanup changed admission error: owner=%v err=%v calls=%d", owner, err, b.closeCalls)
	}
	// The same invalid snapshot still refuses, but root exclusion must no
	// longer be busy after a confirmed cleanup.
	if other, err := open(dir, newModel().dependencies()); other != nil || err != ErrUnavailable {
		t.Fatal("confirmed cleanup retained root exclusion:", err)
	}
	writer, err := serviceaccountstore.Open(dir + "/registry")
	if err != nil {
		t.Fatal("confirmed cleanup retained registry exclusion:", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	for _, uncertain := range []bool{false, true} {
		b := &uncertainCloseSMB{}
		if uncertain {
			b.closeErr = errors.New("PRIVATE unavailable-path cleanup")
		}
		owner, err := OpenWithSMBBackend(dir+"/missing", deps.inventory, b)
		if owner != nil || !errors.Is(err, ErrUnavailable) || errors.Is(err, ErrReview) != uncertain || b.closeCalls != 1 || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("unavailable path cleanup classification: owner=%v err=%v calls=%d", owner, err, b.closeCalls)
		}
	}
}

func TestOwnerBackendTeardownPrecedesJournalRelease(t *testing.T) {
	b := &uncertainCloseSMB{}
	owner, _, dir := fixtureWithSMB(t, b)
	ctx := context.Background()
	account, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, account.ID)
	if err := owner.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := owner.SMB(account.ID).Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	verified := false
	b.onClose = func() error {
		writer, err := smbprovision.Open(dir+"/operations/"+account.ID+"/smb", nil)
		if writer != nil {
			_ = writer.Close()
		}
		if !errors.Is(err, revisionstore.ErrBusy) || writer != nil {
			return errors.New("backend teardown lost its Samba journal authority")
		}
		verified = true
		return nil
	}
	if err := owner.Close(); err != nil || !verified {
		t.Fatal("backend did not retain the real journal until teardown:", err)
	}
	if err := owner.Close(); err != nil || b.closeCalls != 1 {
		t.Fatalf("confirmed close was not idempotent: calls=%d error=%v", b.closeCalls, err)
	}
}

func TestOwnerUncertainBackendCloseRetainsAuthorityWithoutRetry(t *testing.T) {
	const childVariable = "PHANTOWD_OWNER_CLOSE_UNCERTAINTY_DIR"
	dir := os.Getenv(childVariable)
	if dir == "" {
		dir = provision(t)
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestOwnerUncertainBackendCloseRetainsAuthorityWithoutRetry$", "-test.v")
		command.Env = append(os.Environ(), childVariable+"="+dir)
		output, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("isolated uncertainty regression: %v\n%s", err, output)
		}
		if !strings.Contains(string(output), "--- PASS: TestOwnerUncertainBackendCloseRetainsAuthorityWithoutRetry") {
			t.Fatalf("child did not execute the authority regression:\n%s", output)
		}
		// Process exit releases OS descriptors. This is fixture cleanup, not a
		// product recovery mechanism or permission to retry an uncertain close.
		reopened, err := open(dir, newModel().dependencies())
		if err != nil {
			t.Fatal("test-process exit did not release its fixture:", err)
		}
		if err := reopened.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	if os.Getuid() != 0 || os.Geteuid() != 0 {
		t.Fatal("uncertainty child requires the isolated root test lane")
	}
	b := &uncertainCloseSMB{closeErr: errors.New("PRIVATE ambiguous backend teardown")}
	m := newModel()
	deps := m.dependencies()
	deps.smbBackend = b
	owner, err := open(dir, deps)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	account, err := owner.Reserve(ctx, 1, "first", "firstuser")
	if err != nil {
		t.Fatal(err)
	}
	completeUnixIdentity(t, owner, account.ID)
	if err := owner.SMB(account.ID).Begin(ctx, 5); err != nil {
		t.Fatal(err)
	}
	if err := owner.SMB(account.ID).Step(ctx, 1); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); !errors.Is(err, ErrUnavailable) || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("uncertain close did not return redacted unavailability:", err)
	}
	if competing, err := open(dir, m.dependencies()); !errors.Is(err, ErrBusy) || competing != nil {
		if competing != nil {
			_ = competing.Close()
		}
		t.Fatal("uncertain backend close released the owner authority:", err)
	}
	if writer, err := serviceaccountstore.Open(dir + "/registry"); !errors.Is(err, revisionstore.ErrBusy) || writer != nil {
		if writer != nil {
			_ = writer.Close()
		}
		t.Fatal("uncertain backend close released the registry writer lease:", err)
	}
	if writer, err := identityprovision.Open(dir + "/operations/" + account.ID); !errors.Is(err, revisionstore.ErrBusy) || writer != nil {
		if writer != nil {
			_ = writer.Close()
		}
		t.Fatal("uncertain backend close released the native journal:", err)
	}
	if writer, err := smbprovision.Open(dir+"/operations/"+account.ID+"/smb", nil); !errors.Is(err, revisionstore.ErrBusy) || writer != nil {
		if writer != nil {
			_ = writer.Close()
		}
		t.Fatal("uncertain backend close released the Samba journal:", err)
	}
	if _, _, err := owner.Snapshot(context.Background()); !errors.Is(err, ErrUnavailable) {
		t.Fatal("uncertain authority accepted fresh work:", err)
	}
	b.closeErr = nil
	if err := owner.Close(); !errors.Is(err, ErrUnavailable) || b.closeCalls != 1 {
		t.Fatalf("uncertain close was retried or forgotten: calls=%d error=%v", b.closeCalls, err)
	}
}
