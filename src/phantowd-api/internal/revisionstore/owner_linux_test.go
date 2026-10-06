//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package revisionstore

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

func openOwnerTest(t *testing.T) (*OwnedStore[shareconfig.Config], string) {
	t.Helper()
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := OpenOwnedWithCodec(dir, shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := o.Close(); err != nil {
			t.Error("owner cleanup", err)
		}
	})
	return o, dir
}

func TestPolicyOwnerRequiresInitializedStateAndKeepsExclusiveLock(t *testing.T) {
	s, dir := openTest(t)
	s.Close()
	if o, err := OpenOwnedWithCodec(dir, shareCodec()); !errors.Is(err, ErrNotInitialized) {
		if o != nil {
			o.Close()
		}
		t.Fatal("missing state initialized", err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) != 0 {
		t.Fatal("missing state changed", entries, err)
	}
	o, dir := openOwnerTest(t)
	if s, err := Open(dir); !errors.Is(err, ErrBusy) {
		if s != nil {
			s.Close()
		}
		t.Fatal("flock lost", err)
	}
	if _, err := o.Snapshot(nil); !errors.Is(err, ErrInvalid) {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := o.Acquire(ctx, 1); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := o.Commit(ctx, 1, policy(2)); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if got, err := o.Snapshot(context.Background()); err != nil || got.Revision != 1 {
		t.Fatal("cancellation changed state", got, err)
	}
}

func TestPolicyLeasesFencePublicationAndReleaseDefensiveSnapshots(t *testing.T) {
	o, _ := openOwnerTest(t)
	ctx := context.Background()
	first, err := o.Acquire(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Release()
	second, err := o.Acquire(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Release()
	if err := o.Commit(ctx, 1, policy(2)); !errors.Is(err, ErrBusy) {
		t.Fatal("live commit", err)
	}
	if err := o.Close(); !errors.Is(err, ErrBusy) {
		t.Fatal("live close", err)
	}
	got, err := first.Snapshot(ctx)
	if err != nil {
		t.Fatal(err)
	}
	got.Volumes = append(got.Volumes, shareconfig.Volume{ID: "local-mutation"})
	if again, err := second.Snapshot(ctx); err != nil || !reflect.DeepEqual(again, policy(1)) {
		t.Fatal("shared snapshot", again, err)
	}
	if _, err := o.Acquire(ctx, 2); !errors.Is(err, ErrConflict) {
		t.Fatal(err)
	}
	if err := first.Release(); err != nil {
		t.Fatal(err)
	}
	if err := first.Verify(ctx); !errors.Is(err, ErrClosed) {
		t.Fatal("released claim usable", err)
	}
	if err := o.Commit(ctx, 1, policy(2)); !errors.Is(err, ErrBusy) {
		t.Fatal("second claim lost", err)
	}
	second.Release()
	bad := policy(2)
	bad.Users = nil
	if err := o.Commit(ctx, 1, bad); !errors.Is(err, ErrInvalid) {
		t.Fatal("invalid accepted", err)
	}
	if err := o.Commit(ctx, 0, policy(1)); !errors.Is(err, ErrConflict) {
		t.Fatal("stale accepted", err)
	}
	if err := o.Commit(ctx, 1, policy(2)); err != nil {
		t.Fatal("explicit commit", err)
	}
	third, err := o.Acquire(ctx, 2)
	if err != nil {
		t.Fatal(err)
	}
	if err := third.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	third.Release()
	if err := first.Release(); err != nil {
		t.Fatal("idempotent release", err)
	}
}

func TestPolicyClaimsCannotBeForgedCopiedSerializedOrTransferred(t *testing.T) {
	o, _ := openOwnerTest(t)
	other, _ := openOwnerTest(t)
	ctx := context.Background()
	l, err := o.Acquire(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	copied := *l
	for _, bad := range []*PolicyLease[shareconfig.Config]{nil, {}, &copied, {owner: o, revision: 1}, {owner: other, self: l, revision: 1}} {
		if err := bad.Verify(ctx); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad lease verified", err)
		}
		if err := bad.Release(); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad lease released", err)
		}
	}
	// Copy a quiescent Owner only to prove self-identity refusal before locking.
	v := reflect.New(reflect.TypeOf(o).Elem())
	v.Elem().Set(reflect.ValueOf(o).Elem())
	for _, bad := range []*OwnedStore[shareconfig.Config]{nil, {}, v.Interface().(*OwnedStore[shareconfig.Config])} {
		if _, err := bad.Snapshot(ctx); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad owner usable", err)
		}
		if err := bad.Close(); !errors.Is(err, ErrInvalid) {
			t.Fatal("bad owner closed", err)
		}
	}
	for _, value := range []any{o, l} {
		if _, err := json.Marshal(value); err == nil {
			t.Fatal("capability serialized")
		}
	}
	if err := json.Unmarshal([]byte("{}"), l); err == nil {
		t.Fatal("lease deserialized")
	}
	if err := json.Unmarshal([]byte("{}"), o); err == nil {
		t.Fatal("owner deserialized")
	}
	if err := l.Verify(ctx); err != nil {
		t.Fatal("original lease invalidated", err)
	}
}

func TestPolicyOwnerQuarantinesRestoredMutationsAndRetainsClaims(t *testing.T) {
	for _, mutation := range []string{"same-byte-rename", "write-restore", "mode-restore", "link-restore", "delete-restore", "directory-rename-restore", "pending", "unrelated", "watch-loss"} {
		t.Run(mutation, func(t *testing.T) {
			o, dir := openOwnerTest(t)
			ctx := context.Background()
			l, err := o.Acquire(ctx, 1)
			if err != nil {
				t.Fatal(err)
			}
			defer l.Release()
			path := filepath.Join(dir, currentName)
			original, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			must := func(err error) {
				t.Helper()
				if err != nil {
					t.Fatal(err)
				}
			}
			switch mutation {
			case "same-byte-rename":
				must(os.WriteFile(dir+"/replace", original, 0600))
				must(os.Rename(dir+"/replace", path))
			case "write-restore":
				must(os.WriteFile(path, []byte("{broken"), 0600))
				must(os.WriteFile(path, original, 0600))
			case "mode-restore":
				must(os.Chmod(path, 0644))
				must(os.Chmod(path, 0600))
			case "link-restore":
				must(os.Link(path, dir+"/alias"))
				must(os.Remove(dir + "/alias"))
			case "delete-restore":
				must(os.Remove(path))
				must(os.WriteFile(path, original, 0600))
			case "directory-rename-restore":
				must(os.Rename(dir, dir+"-moved"))
				must(os.Rename(dir+"-moved", dir))
			case "pending":
				must(os.WriteFile(filepath.Join(dir, pendingName), original, 0600))
			case "unrelated":
				must(os.WriteFile(dir+"/unrelated", original, 0600))
				must(os.Remove(dir + "/unrelated"))
			case "watch-loss":
				o.mu.Lock()
				must(unix.Close(o.watch))
				o.watch = -1
				o.mu.Unlock()
			}
			for i := 0; i < 2; i++ {
				if err := l.Verify(ctx); !errors.Is(err, ErrReview) {
					t.Fatal("drift revived", err)
				}
				if _, err := o.Snapshot(ctx); !errors.Is(err, ErrReview) {
					t.Fatal("snapshot revived", err)
				}
				if _, err := o.Acquire(ctx, 1); !errors.Is(err, ErrReview) {
					t.Fatal("new claim admitted", err)
				}
				if err := o.Commit(ctx, 1, policy(2)); !errors.Is(err, ErrReview) {
					t.Fatal("retry accepted", err)
				}
			}
			if err := o.Close(); !errors.Is(err, ErrBusy) {
				t.Fatal("claim abandoned in review", err)
			}
			if second, err := Open(dir); !errors.Is(err, ErrBusy) {
				if second != nil {
					second.Close()
				}
				t.Fatal("review flock released", err)
			}
			if data, err := os.ReadFile(path); err != nil || !bytes.Equal(data, original) {
				t.Fatal("evidence changed", err)
			}
			l.Release()
			if _, err := o.Snapshot(ctx); !errors.Is(err, ErrReview) {
				t.Fatal("release cleared review", err)
			}
		})
	}
}

func TestPolicyOwnerPublicationFailuresNeverRetry(t *testing.T) {
	for _, stage := range []string{"write", "sync", "close", "rename", "rename-after-publication", "directory-sync"} {
		t.Run(stage, func(t *testing.T) {
			o, dir := openOwnerTest(t)
			ctx := context.Background()
			published := false
			switch stage {
			case "write":
				o.store.io.write = func(f *os.File, data []byte) (int, error) { n, _ := f.Write(data[:8]); return n, unix.ENOSPC }
			case "sync":
				o.store.io.sync = func(*os.File) error { return unix.EIO }
			case "close":
				o.store.io.close = func(f *os.File) error { f.Close(); return unix.EIO }
			case "rename":
				o.store.io.rename = func(int, string, int, string) error { return unix.EIO }
			case "rename-after-publication":
				published = true
				o.store.io.rename = func(a int, b string, c int, d string) error {
					if err := unix.Renameat(a, b, c, d); err != nil {
						t.Fatal(err)
					}
					return unix.EIO
				}
			case "directory-sync":
				published = true
				o.store.io.syncDir = func(int) error { return unix.EIO }
			}
			if err := o.Commit(ctx, 1, policy(2)); !errors.Is(err, ErrReview) {
				t.Fatal("failure not quarantined", err)
			}
			before, err := os.ReadFile(filepath.Join(dir, currentName))
			if err != nil {
				t.Fatal(err)
			}
			pendingBefore, pendingErr := os.ReadFile(filepath.Join(dir, pendingName))
			for i := 0; i < 2; i++ {
				if err := o.Commit(ctx, 1, policy(2)); !errors.Is(err, ErrReview) {
					t.Fatal("retry", err)
				}
				if _, err := o.Acquire(ctx, 1); !errors.Is(err, ErrReview) {
					t.Fatal("review claim", err)
				}
			}
			after, _ := os.ReadFile(filepath.Join(dir, currentName))
			pendingAfter, pendingErrAfter := os.ReadFile(filepath.Join(dir, pendingName))
			if !bytes.Equal(before, after) || !bytes.Equal(pendingBefore, pendingAfter) || errors.Is(pendingErr, os.ErrNotExist) != errors.Is(pendingErrAfter, os.ErrNotExist) {
				t.Fatal("review altered evidence")
			}
			if err := o.Close(); err != nil {
				t.Fatal(err)
			}
			s, err := Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()
			got, err := s.Load()
			expected := uint64(1)
			if published {
				expected = 2
			}
			if err != nil || !reflect.DeepEqual(got, policy(expected)) {
				t.Fatal("split state", got, err)
			}
		})
	}
}

func TestPolicyOwnerBoundedClaimsConcurrentReadsAndNoDescriptorGrowth(t *testing.T) {
	o, _ := openOwnerTest(t)
	ctx := context.Background()
	countFDs := func() int {
		t.Helper()
		entries, err := os.ReadDir("/proc/self/fd")
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	before := countFDs()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 20; j++ {
				l, err := o.Acquire(ctx, 1)
				if err != nil {
					t.Error(err)
					return
				}
				if err := l.Verify(ctx); err != nil {
					t.Error(err)
				}
				if err := l.Release(); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	leases := make([]*PolicyLease[shareconfig.Config], 0, maxPolicyLeases)
	defer func() {
		for _, l := range leases {
			l.Release()
		}
	}()
	for i := 0; i < maxPolicyLeases; i++ {
		l, err := o.Acquire(ctx, 1)
		if err != nil {
			t.Fatal(err)
		}
		leases = append(leases, l)
	}
	if _, err := o.Acquire(ctx, 1); !errors.Is(err, ErrBusy) {
		t.Fatal("unbounded claims", err)
	}
	for _, l := range leases {
		if err := l.Release(); err != nil {
			t.Fatal(err)
		}
	}
	for revision := uint64(2); revision <= 20; revision++ {
		if err := o.Commit(ctx, revision-1, policy(revision)); err != nil {
			t.Fatal(err)
		}
	}
	if after := countFDs(); after != before {
		t.Fatal("descriptor accumulation", before, after)
	}
}

func TestPolicyOwnerBracketsDecodeAgainstConcurrentRestoredMutation(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	s.Close()
	path := filepath.Join(dir, currentName)
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	armed := false
	codec := shareCodec()
	decode := codec.Decode
	// Trusted test-only codec seam; production adapter always fixes its decoder.
	codec.Decode = func(r io.Reader) (shareconfig.Config, error) {
		doc, err := decode(r)
		if armed {
			armed = false
			if err := os.WriteFile(path, []byte("{broken"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
		}
		return doc, err
	}
	o, err := OpenOwnedWithCodec(dir, codec)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	l, err := o.Acquire(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Release()
	armed = true
	if err := l.Verify(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal("during-read ABA accepted", err)
	}
}

func TestPolicyOwnerCancellationAfterPublicationIsReviewNotNoEffect(t *testing.T) {
	o, dir := openOwnerTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	o.store.io.syncDir = func(fd int) error { err := unix.Fsync(fd); cancel(); return err }
	if err := o.Commit(ctx, 1, policy(2)); !errors.Is(err, ErrReview) {
		t.Fatal("published cancellation misrepresented", err)
	}
	if _, err := o.Snapshot(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal("cancellation auto-recovered", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, currentName))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := shareconfig.Decode(bytes.NewReader(data))
	if err != nil || doc.Revision != 2 {
		t.Fatal("publication lost", doc, err)
	}
}

func TestPolicyOwnerUncertainCloseNeverRetriesDescriptorNumbers(t *testing.T) {
	s, dir := openTest(t)
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := OpenOwnedWithCodec(dir, shareCodec())
	if err != nil {
		t.Fatal(err)
	}
	o.mu.Lock()
	if err := unix.Close(o.watch); err != nil {
		t.Fatal(err)
	}
	o.mu.Unlock()
	// No intervening descriptor allocation: the first Close sees actual EBADF.
	if err := o.Close(); !errors.Is(err, ErrReview) {
		t.Fatal("close uncertainty lost", err)
	}
	if err := o.Close(); !errors.Is(err, ErrReview) {
		t.Fatal("uncertain close retried", err)
	}
	if _, err := o.Snapshot(context.Background()); !errors.Is(err, ErrReview) {
		t.Fatal("close uncertainty revived", err)
	}
	if !o.store.closed || o.watch != -1 {
		t.Fatal("uncertain close did not attempt both resource closures")
	}
}

func TestPolicyOwnerAcquireSerializesAgainstCommitAndClose(t *testing.T) {
	ctx := context.Background()
	for _, operation := range []string{"commit", "close"} {
		t.Run(operation, func(t *testing.T) {
			for attempt := 0; attempt < 16; attempt++ {
				o, _ := openOwnerTest(t)
				start := make(chan struct{})
				var wg sync.WaitGroup
				var lease *PolicyLease[shareconfig.Config]
				var acquireErr, mutationErr error
				wg.Add(2)
				go func() { defer wg.Done(); <-start; lease, acquireErr = o.Acquire(ctx, 1) }()
				go func() {
					defer wg.Done()
					<-start
					if operation == "commit" {
						mutationErr = o.Commit(ctx, 1, policy(2))
					} else {
						mutationErr = o.Close()
					}
				}()
				close(start)
				wg.Wait()
				if lease != nil {
					if acquireErr != nil || !errors.Is(mutationErr, ErrBusy) {
						lease.Release()
						t.Fatal("live claim did not fence", acquireErr, mutationErr)
					}
					if err := lease.Verify(ctx); err != nil {
						lease.Release()
						t.Fatal(err)
					}
					lease.Release()
				} else {
					expected := ErrConflict
					if operation == "close" {
						expected = ErrClosed
					}
					if mutationErr != nil || !errors.Is(acquireErr, expected) {
						t.Fatal("mutation admitted stale claim", acquireErr, mutationErr)
					}
				}
			}
		})
	}
}
