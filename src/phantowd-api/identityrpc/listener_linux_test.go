// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityrpc

import (
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"golang.org/x/sys/unix"
)

func listenerDir(t *testing.T) string {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("root-owned isolated listener tests")
	}
	dir := t.TempDir()
	if os.Chown(dir, 0, 65534) != nil || os.Chmod(dir, 0710) != nil {
		t.Fatal("directory setup")
	}
	return dir
}

func openListener(t *testing.T, dir string, s *Server) *Listener {
	t.Helper()
	l, err := Listen(dir, 65534, s)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	return l
}

func awaitListener(t *testing.T, done <-chan error) error {
	t.Helper()
	select {
	case err := <-done:
		return err
	case <-time.After(3 * time.Second):
		t.Fatal("listener did not stop")
		return nil
	}
}

func TestListenerLifecycle(t *testing.T) {
	s, m := fixture(t)
	s.uid = 0 // only the package-private test seam; production API UID is non-root
	dir := listenerDir(t)
	l := openListener(t, dir, s)
	if other, err := Listen(dir, 65534, s); other != nil || err != ErrBusy {
		t.Fatal("duplicate owner", other, err)
	}
	if !l.socketSafe(l.identity) {
		t.Fatal("socket metadata")
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, socketName), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	r, err := Call(ctx, c, Request{Version: 1, Action: "step", AccountID: "fixture", Revision: 1})
	if err != nil || r.Phase != identityprovision.GroupConfirmed {
		t.Fatal(r, err)
	}
	if err := l.Run(ctx); err != ErrChannel {
		t.Fatal("second Run", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitListener(t, done); err != nil || m.calls != 1 {
		t.Fatal(err, m.calls)
	}
	if _, err := os.Lstat(filepath.Join(dir, socketName)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("socket not removed", err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	openListener(t, dir, s) // lease released; directory itself preserved
}

func TestListenerSetupRefusals(t *testing.T) {
	s, _ := fixture(t)
	for _, kind := range []string{"file", "symlink", "directory", "foreign-socket", "wrong-mode-socket", "hardlinked-socket", "live-socket"} {
		t.Run(kind, func(t *testing.T) {
			dir := listenerDir(t)
			path := filepath.Join(dir, socketName)
			switch kind {
			case "file":
				if err := os.WriteFile(path, []byte("preserve"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Symlink("missing-target", path); err != nil {
					t.Fatal(err)
				}
			case "directory":
				if err := os.Mkdir(path, 0700); err != nil {
					t.Fatal(err)
				}
			default:
				raw, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
				if err != nil {
					t.Fatal(err)
				}
				raw.SetUnlinkOnClose(false)
				defer raw.Close()
				if os.Chown(path, 0, 65534) != nil || os.Chmod(path, 0620) != nil {
					t.Fatal("socket setup")
				}
				if kind != "live-socket" {
					raw.Close()
				}
				if kind == "foreign-socket" {
					if err := os.Chown(path, 65534, 65534); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "wrong-mode-socket" {
					if err := os.Chmod(path, 0666); err != nil {
						t.Fatal(err)
					}
				}
				if kind == "hardlinked-socket" {
					if err := os.Link(path, filepath.Join(dir, "other")); err != nil {
						t.Fatal(err)
					}
				}
			}
			before, err := os.Lstat(path)
			if err != nil {
				t.Fatal(err)
			}
			if l, err := Listen(dir, 65534, s); l != nil || err != ErrChannel {
				t.Fatal(l, err)
			}
			after, err := os.Lstat(path)
			if err != nil || !os.SameFile(before, after) {
				t.Fatal("changed refused target", err)
			}
		})
	}
	for _, mode := range []os.FileMode{0700, 0711, 0770, 0777} {
		dir := listenerDir(t)
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
		if l, err := Listen(dir, 65534, s); l != nil || err != ErrChannel {
			t.Fatal(mode, l, err)
		}
	}
	dir := listenerDir(t)
	link := filepath.Join(t.TempDir(), "linked")
	if err := os.Symlink(dir, link); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(link, 65534, s); l != nil || err != ErrChannel {
		t.Fatal(l, err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(dir, 65534, s); l != nil || err != ErrChannel {
		t.Fatal(l, err)
	}
	for _, path := range []string{"relative", dir + "/../"} {
		if l, err := Listen(path, 65534, s); l != nil || err != ErrInvalid {
			t.Fatal(l, err)
		}
	}
	if l, err := Listen(dir, 0, s); l != nil || err != ErrInvalid {
		t.Fatal(l, err)
	}
}

func TestListenerStaleRecoveryAndReplacement(t *testing.T) {
	s, _ := fixture(t)
	dir := listenerDir(t)
	l := openListener(t, dir, s)
	// Model abrupt process loss: close kernel listener and lease, keep pathname.
	l.socket.Close()
	unix.Close(l.dir)
	l.once.Do(func() { close(l.done) })
	l = openListener(t, dir, s)
	path := filepath.Join(dir, socketName)
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != ErrChannel {
		t.Fatal("replacement not detected", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "replacement" {
		t.Fatal("replacement removed", err)
	}
}

func TestListenerLongDirectoryAndCloseBeforeRun(t *testing.T) {
	s, _ := fixture(t)
	dir := filepath.Join(listenerDir(t), strings.Repeat("a", 110))
	if err := os.Mkdir(dir, 0710); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 0, 65534); err != nil {
		t.Fatal(err)
	}
	l := openListener(t, dir, s)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := l.Run(context.Background()); err != ErrChannel {
		t.Fatal(err)
	}
	var zero Listener
	if err := zero.Close(); err != nil {
		t.Fatal(err)
	}
	if err := zero.Run(context.Background()); err != ErrChannel {
		t.Fatal(err)
	}
}

type drainingOperation struct {
	entered chan struct{}
	release chan struct{}
	journal identityprovision.Journal
}

func (o *drainingOperation) Load(ctx context.Context) (identityprovision.Journal, error) {
	close(o.entered)
	<-ctx.Done()
	<-o.release // model trusted backend which needs extra time to drain
	return o.journal, ctx.Err()
}
func (*drainingOperation) Step(context.Context, uint64) error { return ErrChannel }

func TestListenerCancellationDrainsOwner(t *testing.T) {
	s, _ := fixture(t)
	s.uid = 0
	op := &drainingOperation{entered: make(chan struct{}), release: make(chan struct{})}
	s.operation = op
	dir := listenerDir(t)
	l := openListener(t, dir, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, socketName), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	if err := send(c, Request{Version: 1, Action: "status", AccountID: "fixture"}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-op.entered:
	case <-time.After(time.Second):
		t.Fatal("backend not entered")
	}
	cancel()
	closing := make(chan error, 1)
	go func() { closing <- l.Close() }()
	select {
	case err := <-closing:
		t.Fatal("closed before drain", err)
	case <-time.After(20 * time.Millisecond):
	}
	if other, err := Listen(dir, 65534, s); other != nil || err != ErrBusy {
		t.Fatal("lease released before drain", other, err)
	}
	close(op.release)
	if err := awaitListener(t, closing); err != nil {
		t.Fatal(err)
	}
	if err := awaitListener(t, done); err != nil {
		t.Fatal(err)
	}
}

func TestListenerRunCloseRace(t *testing.T) {
	s, _ := fixture(t)
	for i := 0; i < 30; i++ {
		l := openListener(t, listenerDir(t), s)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() {
			defer wg.Done()
			err := l.Run(context.Background())
			if err != nil && err != ErrChannel {
				t.Error(err)
			}
		}()
		for j := 0; j < 2; j++ {
			go func() {
				defer wg.Done()
				if err := l.Close(); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
	}
}

func TestProtectedListenerRealClient(t *testing.T) {
	s, m := fixture(t)
	// Direct /tmp child: testing.T's private parent is not API-traversable.
	dir, err := os.MkdirTemp("", "identity-protected-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // only this test-created temporary directory
	if os.Chown(dir, 0, 65534) != nil || os.Chmod(dir, 0710) != nil {
		t.Fatal("directory setup")
	}
	l := openListener(t, dir, s)
	defer l.Close() // before removing directory, not just t.Cleanup
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	path := filepath.Join(dir, socketName)
	rootClient, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Call(ctx, rootClient, Request{1, "step", "fixture", 1}); err != ErrChannel {
		t.Fatal("root client admitted", err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(exe)
	if err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(dir, "client-test")
	if err := os.WriteFile(child, data, 0755); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, child, "-test.run=^TestUnprivilegedClient$")
	cmd.Env = []string{"PHANTOWD_RPC_CHILD=1", "PHANTOWD_RPC_SOCKET=" + path, "GORACE=atexit_sleep_ms=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	if err := cmd.Run(); err != nil {
		t.Fatal(err)
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := awaitListener(t, done); err != nil || m.calls != 1 {
		t.Fatal(err, m.calls)
	}
}

func TestListenerIdleClientsCancel(t *testing.T) {
	s, m := fixture(t)
	s.uid = 0
	dir := listenerDir(t)
	l := openListener(t, dir, s)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- l.Run(ctx) }()
	for i := 0; i < 64; i++ {
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: filepath.Join(dir, socketName), Net: "unix"})
		if errors.Is(err, unix.EAGAIN) {
			continue // bounded kernel backlog may refuse before userspace accepts
		}
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
	}
	cancel()
	if err := awaitListener(t, done); err != nil || m.calls != 0 {
		t.Fatal(err, m.calls)
	}
}

func TestListenerKernelBacklogBound(t *testing.T) {
	s, m := fixture(t)
	l := openListener(t, listenerDir(t), s)
	// Do not start Run: isolate the kernel backlog from worker scheduling,
	// deadlines or close. Root bypasses pathname permission checks here.
	path := "/proc/self/fd/" + strconv.Itoa(l.dir) + "/" + socketName
	accepted := 0
	for i := 0; i < 64; i++ {
		fd, err := unix.Socket(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_NONBLOCK|unix.SOCK_CLOEXEC, 0)
		if err != nil {
			t.Fatal(err)
		}
		defer unix.Close(fd)
		err = unix.Connect(fd, &unix.SockaddrUnix{Name: path})
		if errors.Is(err, unix.EAGAIN) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		accepted++
	}
	// Linux allows one additional queued connection beyond listen(backlog).
	if accepted < 1 || accepted > 9 || m.calls != 0 {
		t.Fatal("unbounded backlog", accepted, m.calls)
	}
	if !l.socketSafe(l.identity) {
		t.Fatal("listener changed")
	}
}
