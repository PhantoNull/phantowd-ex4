// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityprovision

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/revisionstore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

type fakeBackend struct {
	group, user         bool
	calls, observations int
	failCommand         bool
	failObservation     int
	onCommand           func(string)
}

func (b *fakeBackend) Observe(context.Context) (unixidentity.Snapshot, error) {
	b.observations++
	if b.observations == b.failObservation {
		return unixidentity.Snapshot{}, errors.New("sensitive backend diagnostic")
	}
	passwd, group := "root:x:0:0:root:/root:/bin/sh\n", "root:x:0:\n"
	if b.user {
		passwd += "qpjournal:x:21000:21000::/:/sbin/nologin\n"
	}
	if b.group {
		group += "qpjournal:x:21000:\n"
	}
	return unixidentity.Parse(strings.NewReader(passwd), strings.NewReader(group))
}

func (b *fakeBackend) create(kind string) error {
	b.calls++
	if b.onCommand != nil {
		b.onCommand(kind)
	}
	if b.failCommand {
		return errors.New("sensitive command diagnostic")
	}
	if kind == "group" {
		b.group = true
	} else {
		b.user = true
	}
	return nil
}
func (b *fakeBackend) CreateGroup(context.Context, serviceaccounts.Account) error {
	return b.create("group")
}
func (b *fakeBackend) CreateUser(context.Context, serviceaccounts.Account) error {
	return b.create("user")
}

func privateJournalDirectory(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func beginFixture(t *testing.T) (*Store, serviceaccounts.Registry, *fakeBackend, string) {
	t.Helper()
	dir := privateJournalDirectory(t)
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	r, b := fixtureRegistry(t), &fakeBackend{}
	obs, _ := b.Observe(context.Background())
	if err := s.Begin(r, "fixture", obs); err != nil {
		t.Fatal(err)
	}
	return s, r, b, dir
}

func TestProvisionSequenceAndBoundaries(t *testing.T) {
	s, r, b, dir := beginFixture(t)
	b.onCommand = func(kind string) {
		f, err := os.Open(filepath.Join(dir, "identity-operation.json"))
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		j, err := Decode(f)
		want := GroupIntent
		if kind == "user" {
			want = UserIntent
		}
		if err != nil || j.Phase != want {
			t.Fatal("command preceded durable intent", j, err)
		}
	}
	for _, step := range []struct {
		rev   uint64
		phase string
	}{{1, GroupConfirmed}, {3, UnixConfirmed}, {5, UnixConfirmed}} {
		if err := s.Step(context.Background(), step.rev, r, b); err != nil {
			t.Fatal(err)
		}
		j, err := s.Load()
		if err != nil || j.Phase != step.phase || j.Account != r.Accounts[0] {
			t.Fatal(j, err)
		}
	}
	if b.calls != 2 {
		t.Fatal("commands replayed", b.calls)
	}
	if err := s.Step(context.Background(), 1, r, b); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if again, err := Open(dir); !errors.Is(err, revisionstore.ErrBusy) {
		if again != nil {
			again.Close()
		}
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Step(context.Background(), 5, r, b); err != nil || b.calls != 2 {
		t.Fatal(err, b.calls)
	}
	b.user = false
	if err := s.Step(context.Background(), 5, r, b); !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	if err := s.Step(context.Background(), 6, r, b); !errors.Is(err, ErrReview) || b.calls != 2 {
		t.Fatal(err)
	}
}

func TestProvisionRefusesAdoptionFailuresAndStaleState(t *testing.T) {
	for _, scenario := range []string{"existing", "enabled", "invalid-snapshot", "stale-registry", "group-only-drift", "user-only-drift", "command-error", "post-observation-error", "pre-observation-error", "cancelled", "closed"} {
		t.Run(scenario, func(t *testing.T) {
			s, r, b, _ := beginFixture(t)
			ctx := context.Background()
			switch scenario {
			case "existing", "enabled", "invalid-snapshot":
				other, err := Open(privateJournalDirectory(t))
				if err != nil {
					t.Fatal(err)
				}
				defer other.Close()
				b.user, b.group = true, true
				obs, _ := b.Observe(ctx)
				if scenario == "enabled" {
					r.Accounts[0].State = serviceaccounts.Enabled
				}
				if scenario == "invalid-snapshot" {
					obs = unixidentity.Snapshot{}
				}
				if err := other.Begin(r, "fixture", obs); err == nil {
					t.Fatal("adoption accepted")
				}
				return
			case "stale-registry":
				r.Revision++
			case "group-only-drift":
				b.group = true
			case "user-only-drift":
				if err := s.Step(ctx, 1, r, b); err != nil {
					t.Fatal(err)
				}
				b.group, b.user = false, true
				if err := s.Step(ctx, 3, r, b); !errors.Is(err, ErrReview) || b.calls != 1 {
					t.Fatal(err)
				}
				return
			case "command-error":
				b.failCommand = true
			case "post-observation-error":
				b.failObservation = b.observations + 2
			case "pre-observation-error":
				b.failObservation = b.observations + 1
			case "cancelled":
				var cancel context.CancelFunc
				ctx, cancel = context.WithCancel(ctx)
				cancel()
			case "closed":
				s.Close()
			}
			err := s.Step(ctx, 1, r, b)
			if err == nil || strings.Contains(err.Error(), "sensitive") {
				t.Fatal("failure not redacted", err)
			}
			want := 0
			if scenario == "command-error" || scenario == "post-observation-error" {
				want = 1
			}
			if b.calls != want {
				t.Fatal("unexpected command", b.calls)
			}
			if want == 1 {
				j, err := s.Load()
				if err != nil || j.Phase != ReviewRequired {
					t.Fatal(j, err)
				}
			}
		})
	}
}

func TestProvisionConcurrentSteps(t *testing.T) {
	s, r, b, _ := beginFixture(t)
	var wg sync.WaitGroup
	errs := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); errs <- s.Step(context.Background(), 1, r, b) }()
	}
	wg.Wait()
	close(errs)
	ok, stale := 0, 0
	for err := range errs {
		if err == nil {
			ok++
		} else if errors.Is(err, ErrConflict) {
			stale++
		} else {
			t.Fatal(err)
		}
	}
	if ok != 1 || stale != 1 || b.calls != 1 {
		t.Fatal(ok, stale, b.calls)
	}
}

func TestProvisionCommitFailureNeverReplaysCommands(t *testing.T) {
	for _, phase := range []string{"intent", "confirmation"} {
		t.Run(phase, func(t *testing.T) {
			s, r, b, dir := beginFixture(t)
			pending := filepath.Join(dir, ".identity-operation.pending")
			obstruct := func() {
				if err := os.Mkdir(pending, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if phase == "intent" {
				obstruct()
			} else {
				b.onCommand = func(string) { obstruct() }
			}
			if err := s.Step(context.Background(), 1, r, b); err == nil {
				t.Fatal("commit failure hidden")
			}
			wantCalls, wantPhase := 0, Reserved
			if phase == "confirmation" {
				wantCalls, wantPhase = 1, GroupIntent
			}
			j, err := s.Load()
			if err != nil || j.Phase != wantPhase || b.calls != wantCalls {
				t.Fatal(j, err, b.calls)
			}
			// Remove only this empty, test-created obstruction. The operation
			// record itself is never reset or rewritten directly.
			if err := os.Remove(pending); err != nil {
				t.Fatal(err)
			}
			if phase == "confirmation" {
				if err := s.Step(context.Background(), 2, r, b); !errors.Is(err, ErrReview) || b.calls != 1 {
					t.Fatal(err, b.calls)
				}
			}
		})
	}
}

func TestProvisionCancelledAfterDispatchAndPrivateDirectory(t *testing.T) {
	s, r, b, _ := beginFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b.onCommand = func(string) { cancel() }
	if err := s.Step(ctx, 1, r, b); !errors.Is(err, ErrReview) {
		t.Fatal(err)
	}
	j, err := s.Load()
	if err != nil || j.Phase != ReviewRequired || b.calls != 1 {
		t.Fatal(j, err)
	}
	dir := privateJournalDirectory(t)
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	if opened, err := Open(dir); !errors.Is(err, revisionstore.ErrUnsafe) {
		if opened != nil {
			opened.Close()
		}
		t.Fatal(err)
	}
}

// A real child-process exit bypasses all defers after the persisted dispatch
// record, before any success receipt. Only a private modeled backend is used.
func TestProvisionInterruptedProcess(t *testing.T) {
	if dir := os.Getenv("PHANTOWD_TEST_IDENTITY_JOURNAL"); dir != "" {
		s, err := Open(dir)
		if err != nil {
			t.Fatal(err)
		}
		r, b := fixtureRegistry(t), &fakeBackend{}
		obs, _ := b.Observe(context.Background())
		if err := s.Begin(r, "fixture", obs); err != nil {
			t.Fatal(err)
		}
		rev := uint64(1)
		if os.Getenv("PHANTOWD_TEST_IDENTITY_PHASE") == "user" {
			if err := s.Step(context.Background(), 1, r, b); err != nil {
				t.Fatal(err)
			}
			rev = 3
		}
		b.onCommand = func(string) { os.Exit(23) }
		_ = s.Step(context.Background(), rev, r, b)
		t.Fatal("interruption not reached")
	}
	for _, phase := range []string{"group", "user"} {
		t.Run(phase, func(t *testing.T) {
			dir := privateJournalDirectory(t)
			cmd := exec.Command(os.Args[0], "-test.run=^TestProvisionInterruptedProcess$")
			cmd.Env = append(os.Environ(), "PHANTOWD_TEST_IDENTITY_JOURNAL="+dir, "PHANTOWD_TEST_IDENTITY_PHASE="+phase)
			output, err := cmd.CombinedOutput()
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() != 23 {
				t.Fatalf("child %v: %s", err, output)
			}
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			j, err := s.Load()
			if err != nil {
				t.Fatal(err)
			}
			want := GroupIntent
			if phase == "user" {
				want = UserIntent
			}
			if j.Phase != want {
				t.Fatal(j)
			}
			b := &fakeBackend{} // Even complete absence never authorizes replay.
			if err := s.Step(context.Background(), j.Revision, fixtureRegistry(t), b); !errors.Is(err, ErrReview) {
				t.Fatal(err)
			}
			if b.calls != 0 || b.observations != 0 {
				t.Fatal("resumed intent invoked backend")
			}
			j, err = s.Load()
			if err != nil || j.Phase != ReviewRequired {
				t.Fatal(j, err)
			}
		})
	}
}
