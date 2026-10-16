//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policyevidencefs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/policyevidence"
	"golang.org/x/sys/unix"
)

const installation = "11111111222233334444555555555555"
const policyJSON = `{"format":"phantowd-nas-service-config","schema_version":1,"revision":2,"file_services":{"format":"phantowd-file-service-config","schema_version":1,"revision":2,"shares":{"format":"phantowd-share-config","schema_version":1,"revision":2,"volumes":[],"users":[],"shares":[]},"nfs":{"format":"phantowd-nfs-policy","schema_version":1,"revision":2,"volume_revision":2,"exports":[]}},"iscsi":{"format":"phantowd-iscsi-policy","schema_version":1,"revision":2,"volume_revision":2,"backings":[],"targets":[]}}`

func fixture(t *testing.T, current, intent, receipt []byte) string {
	t.Helper()
	root := t.TempDir()
	if err := os.Chmod(root, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"policy", "operations"} {
		if err := os.Mkdir(filepath.Join(root, name), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range map[string][]byte{"policy/nas-services.json": current, "operations/intent.json": intent, "operations/receipt.json": receipt} {
		if data != nil {
			if err := os.WriteFile(filepath.Join(root, name), data, 0600); err != nil {
				t.Fatal(err)
			}
		}
	}
	return root
}
func records(current, base []byte) ([]byte, []byte) {
	hash := func(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }
	r := map[string]any{"format": policyevidence.IntentFormat, "schema_version": 1, "installation_id": installation, "operation_id": "aaaaaaaabbbbccccddddeeeeeeeeeeee", "base_revision": 1, "next_revision": 2, "base_sha256": hash(base), "next_sha256": hash(current)}
	i, _ := json.Marshal(r)
	r["format"], r["phase"] = policyevidence.ReceiptFormat, "local-confirmed"
	receipt, _ := json.Marshal(r)
	return i, receipt
}
func openSupported(t *testing.T, root string) *Observer {
	t.Helper()
	a, err := Open(context.Background(), root, installation)
	if errors.Is(err, ErrUnsupported) {
		if a != nil {
			t.Fatal("unsupported open returned authority")
		}
		t.Skip("kernel lacks required unique mount identity; no fallback accepted")
	}
	if err != nil {
		if a != nil {
			a.Close()
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.Close(); err != nil {
			t.Error(err)
		}
	})
	return a
}

func TestUnsupportedKernelNeverDegradesMountIdentity(t *testing.T) {
	root := fixture(t, []byte(policyJSON), nil, nil)
	a, err := Open(context.Background(), root, installation)
	if errors.Is(err, ErrUnsupported) {
		if a != nil {
			t.Fatal("degraded authority")
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	d, err := a.Observe(context.Background())
	if err != nil || d.Kind() != policyevidence.NoRecordedOperation {
		t.Fatal(d, err)
	}
}

func TestRetainedCompleteRolesMatchWithoutPolicyLockGap(t *testing.T) {
	current := []byte(policyJSON)
	base := []byte(strings.ReplaceAll(policyJSON, ":2", ":1"))
	intent, receipt := records(current, base)
	for _, tc := range []struct {
		name                     string
		current, intent, receipt []byte
		kind                     policyevidence.Kind
	}{
		{"no-operation", current, nil, nil, policyevidence.NoRecordedOperation},
		{"intent-base", base, intent, nil, policyevidence.IntentBaseObserved},
		{"publication-unconfirmed", current, intent, nil, policyevidence.PublicationUnconfirmed},
		{"local-confirmation", current, intent, receipt, policyevidence.LocalConfirmationObserved},
		{"inconsistent", base, intent, receipt, policyevidence.InconsistentEvidence},
		{"incomplete", nil, intent, receipt, policyevidence.IncompleteEvidence},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixture(t, tc.current, tc.intent, tc.receipt)
			a := openSupported(t, root)
			before, _ := os.ReadDir("/proc/self/fd")
			for range 10 {
				d, err := a.Observe(context.Background())
				if err != nil || d.Kind() != tc.kind {
					t.Fatal(d, err)
				}
				other, err := naspolicystore.Open(filepath.Join(root, "policy"))
				if other != nil {
					other.Close()
				}
				if !errors.Is(err, naspolicystore.ErrBusy) {
					t.Fatal("actual policy writer entered", err)
				}
			}
			after, _ := os.ReadDir("/proc/self/fd")
			if len(before) != len(after) {
				t.Fatal("descriptor growth")
			}
			if err := a.Close(); err != nil {
				t.Fatal(err)
			}
			other, err := naspolicystore.Open(filepath.Join(root, "policy"))
			if err != nil {
				t.Fatal("lock not released", err)
			}
			other.Close()
		})
	}
}

func TestInputPrivacyAndZeroCopiedHandles(t *testing.T) {
	for _, v := range []Observer{{}} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("serialized zero handle")
		}
		if strings.Contains(fmt.Sprintf("%#v", v), "state:") {
			t.Fatal("format leak")
		}
	}
	var zero Observer
	if _, err := zero.Observe(context.Background()); err != ErrInvalid {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{}`), &zero); err != ErrInvalid {
		t.Fatal(err)
	}
	for _, root := range []string{"relative", "/tmp/../tmp"} {
		if a, err := Open(context.Background(), root, installation); err != ErrInvalid || a != nil {
			t.Fatal("unsafe request shape")
		}
	}
	root := fixture(t, []byte(policyJSON), nil, nil)
	if a, err := Open(nil, root, installation); err != ErrInvalid || a != nil {
		t.Fatal("nil context")
	}
	if a, err := Open(context.Background(), root, "PRIVATE"); err != ErrInvalid || a != nil || strings.Contains(err.Error(), "PRIVATE") {
		t.Fatal("identifier validation/privacy")
	}
	a := openSupported(t, root)
	copied := *a
	if _, err := copied.Observe(context.Background()); err != ErrInvalid {
		t.Fatal("copied authority")
	}
	if copied.Close() != ErrInvalid {
		t.Fatal("copy released original")
	}
	for _, v := range []any{a, *a} {
		if _, err := json.Marshal(v); err == nil {
			t.Fatal("serialized authority")
		}
		for _, format := range []string{"%v", "%+v", "%#v"} {
			s := fmt.Sprintf(format, v)
			if strings.Contains(s, root) || strings.Contains(s, installation) || !strings.Contains(s, "private") {
				t.Fatal("authority disclosure")
			}
		}
	}
}

func TestNamespaceAndObjectRefusals(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(string) error
	}{
		{"unknown-root", func(r string) error { return os.WriteFile(filepath.Join(r, "unknown"), []byte("x"), 0600) }},
		{"unknown-policy", func(r string) error { return os.WriteFile(filepath.Join(r, "policy/intent.json"), []byte("x"), 0600) }},
		{"unknown-operation", func(r string) error { return os.WriteFile(filepath.Join(r, "operations/unknown"), []byte("x"), 0600) }},
		{"wrong-mode", func(r string) error { return os.Chmod(filepath.Join(r, "policy/nas-services.json"), 0644) }},
		{"empty-record", func(r string) error { return os.WriteFile(filepath.Join(r, "operations/intent.json"), []byte{}, 0600) }},
		{"oversize-record", func(r string) error {
			return os.WriteFile(filepath.Join(r, "operations/intent.json"), make([]byte, 4097), 0600)
		}},
		{"fifo", func(r string) error { return unix.Mkfifo(filepath.Join(r, "operations/intent.json"), 0600) }},
		{"symlink", func(r string) error {
			return os.Symlink(filepath.Join(r, "policy/nas-services.json"), filepath.Join(r, "operations/intent.json"))
		}},
		{"hardlink", func(r string) error {
			return os.Link(filepath.Join(r, "policy/nas-services.json"), filepath.Join(r, "operations/intent.json"))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := fixture(t, []byte(policyJSON), nil, nil)
			probe, err := Open(context.Background(), root, installation)
			if errors.Is(err, ErrUnsupported) {
				t.Skip("unique mount identity unavailable")
			}
			if err != nil {
				t.Fatal(err)
			}
			probe.Close()
			if err := tc.mutate(root); err != nil {
				t.Fatal(err)
			}
			a, err := Open(context.Background(), root, installation)
			if a != nil {
				a.Close()
			}
			if err == nil {
				t.Fatal("unsafe evidence accepted")
			}
		})
	}
}

func TestPendingIsMetadataOnlyAndReviewRetainsActualLock(t *testing.T) {
	root := fixture(t, []byte(policyJSON), nil, nil)
	if err := os.WriteFile(filepath.Join(root, "policy/.nas-services.pending"), []byte("not decoded"), 0600); err != nil {
		t.Fatal(err)
	}
	a := openSupported(t, root)
	reads := 0
	a.state.readAt = func(*os.File, []byte, int64) (int, error) { reads++; return 0, io.ErrUnexpectedEOF }
	if d, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) || d.Kind() != "" || reads != 0 {
		t.Fatal("pending content adopted or read")
	}
	other, err := naspolicystore.Open(filepath.Join(root, "policy"))
	if other != nil {
		other.Close()
	}
	if !errors.Is(err, naspolicystore.ErrBusy) {
		t.Fatal("pending review dropped policy lock")
	}
}

func TestWritableOpenCloseWithNoByteChangeLatchesReview(t *testing.T) {
	root := fixture(t, []byte(policyJSON), nil, nil)
	a := openSupported(t, root)
	f, err := os.OpenFile(filepath.Join(root, "policy/nas-services.json"), os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if d, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) || d.Kind() != "" {
			t.Fatal("write-close history lost")
		}
	}
}

func TestReadFailureAndCancellationPreservePrivateStickyReview(t *testing.T) {
	for _, scenario := range []string{"reader", "cancel"} {
		t.Run(scenario, func(t *testing.T) {
			root := fixture(t, []byte(policyJSON), nil, nil)
			a := openSupported(t, root)
			pre, cancelPre := context.WithCancel(context.Background())
			cancelPre()
			if _, err := a.Observe(pre); !errors.Is(err, context.Canceled) {
				t.Fatal(err)
			}
			if _, err := a.Observe(context.Background()); err != nil {
				t.Fatal("pre-admission cancellation poisoned lifetime", err)
			}
			ctx, cancel := context.WithCancelCause(context.Background())
			defer cancel(nil)
			if scenario == "reader" {
				a.state.readAt = func(*os.File, []byte, int64) (int, error) { return 0, errors.New("PRIVATE READER") }
			} else {
				a.state.beforeMatch = func() { cancel(errors.New("PRIVATE CAUSE")) }
			}
			d, err := a.Observe(ctx)
			if !errors.Is(err, ErrReview) || d.Kind() != "" || strings.Contains(err.Error(), "PRIVATE") {
				t.Fatal("uncertain result escaped", d, err)
			}
			if scenario == "cancel" && !errors.Is(err, context.Canceled) {
				t.Fatal("standard context cause lost")
			}
			a.state.readAt = func(f *os.File, b []byte, o int64) (int, error) { return f.ReadAt(b, o) }
			a.state.beforeMatch = nil
			if _, err := a.Observe(context.Background()); !errors.Is(err, ErrReview) {
				t.Fatal("restoration cleared review")
			}
		})
	}
}

func TestSerializedConcurrentObservations(t *testing.T) {
	a := openSupported(t, fixture(t, []byte(policyJSON), nil, nil))
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if d, err := a.Observe(context.Background()); err != nil || d.Kind() != policyevidence.NoRecordedOperation {
				t.Error("concurrent observation", err)
			}
		}()
	}
	wg.Wait()
}

func TestCloseUncertaintyDoesNotRetryOrReleaseRemainingLocks(t *testing.T) {
	root := fixture(t, []byte(policyJSON), nil, nil)
	a, err := Open(context.Background(), root, installation)
	if errors.Is(err, ErrUnsupported) {
		t.Skip("unique mount identity unavailable")
	}
	if err != nil {
		t.Fatal(err)
	}
	// Controlled fault returns without performing close. Fixture teardown knows
	// those descriptors remain open; this is not a production raw-close retry.
	calls := 0
	a.state.closeFile = func(*os.File) error { calls++; return unix.EIO }
	if a.Close() != ErrReview || a.Close() != ErrReview || calls != 1 {
		t.Fatal("uncertain close retried")
	}
	if _, err := a.Observe(context.Background()); err != ErrReview {
		t.Fatal(err)
	}
	other, err := naspolicystore.Open(filepath.Join(root, "policy"))
	if other != nil {
		other.Close()
	}
	if !errors.Is(err, naspolicystore.ErrBusy) {
		t.Fatal("uncertainty released policy lock")
	}
	for _, roster := range [][3]object{a.state.files, a.state.dirs} {
		for _, o := range roster {
			if o.file != nil {
				o.file.Close()
			}
		}
	}
	unix.Close(a.state.watch)
}
