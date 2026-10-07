// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityowner

import (
	"context"
	"errors"
	"os"
	"os/exec"
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
