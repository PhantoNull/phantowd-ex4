// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityrpc

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/unixidentity"
)

type model struct {
	group, user, fail bool
	calls             int
}

func (m *model) Observe(context.Context) (unixidentity.Snapshot, error) {
	p, g := "root:x:0:0::/:/bin/sh\n", "root:x:0:\n"
	if m.group {
		g += "rpcfixture:x:21000:\n"
	}
	if m.user {
		p += "rpcfixture:x:21000:21000::/:/sbin/nologin\n"
	}
	return unixidentity.Parse(strings.NewReader(p), strings.NewReader(g))
}
func (m *model) CreateGroup(context.Context, serviceaccounts.Account) error {
	m.calls++
	m.group = true
	if m.fail {
		return errors.New("PRIVATE backend detail")
	}
	return nil
}
func (m *model) CreateUser(context.Context, serviceaccounts.Account) error {
	m.calls++
	m.user = true
	return nil
}

func fixture(t *testing.T) (*Server, *model) {
	t.Helper()
	if os.Getuid() != 0 {
		t.Skip("root-owned channel integration runs in isolated container")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	j, err := identityprovision.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { j.Close() })
	r, _ := serviceaccounts.New(21000, 21000)
	r, err = r.Create(1, "fixture", "rpcfixture", serviceaccounts.Reservations{UIDs: []uint32{}, GIDs: []uint32{}, Names: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	m := &model{}
	obs, _ := m.Observe(context.Background())
	if err := j.Begin(r, "fixture", obs); err != nil {
		t.Fatal(err)
	}
	s, err := New(65534, j, func() (serviceaccounts.Registry, error) { return r, nil }, m)
	if err != nil {
		t.Fatal(err)
	}
	return s, m
}

func pair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: filepath.Join(t.TempDir(), "sock"), Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	c, err := net.DialUnix("unix", nil, listener.Addr().(*net.UnixAddr))
	if err != nil {
		t.Fatal(err)
	}
	s, err := listener.AcceptUnix()
	if err != nil {
		c.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close(); s.Close() })
	return s, c
}

func exchange(t *testing.T, s *Server, req Request) Response {
	t.Helper()
	server, client := pair(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), server) }()
	r, err := Call(context.Background(), client, req)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	return r
}

func TestJournalChannelSequence(t *testing.T) {
	s, m := fixture(t)
	// Package-private root loopback seam; public New always refuses API UID 0.
	s.uid = 0
	for _, tc := range []struct {
		action      string
		revision    uint64
		code, phase string
		result      uint64
	}{
		{"status", 0, "ok", "reserved", 1},
		{"step", 2, "conflict", "", 0},
		{"step", 1, "ok", "group-confirmed", 3},
		{"step", 1, "conflict", "", 0},
		{"status", 0, "ok", "group-confirmed", 3},
		{"step", 3, "ok", "unix-confirmed", 5},
		{"step", 5, "ok", "unix-confirmed", 5},
	} {
		r := exchange(t, s, Request{1, tc.action, "fixture", tc.revision})
		if r.Code != tc.code || r.Phase != tc.phase || r.Revision != tc.result {
			t.Fatal(r, tc)
		}
	}
	if m.calls != 2 {
		t.Fatal("command replay", m.calls)
	}
	if r := exchange(t, s, Request{1, "step", "other", 5}); r.Code != "conflict" {
		t.Fatal(r)
	}
}

func TestRefusalAndReview(t *testing.T) {
	s, m := fixture(t)
	if _, err := New(0, s.journal, s.registry, m); err != ErrInvalid {
		t.Fatal(err)
	}
	if _, err := New(1, nil, s.registry, m); err != ErrInvalid {
		t.Fatal(err)
	}
	server, client := pair(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), server) }()
	if _, err := Call(context.Background(), client, Request{1, "step", "fixture", 1}); err == nil {
		t.Fatal("root peer accepted as API")
	}
	if err := <-done; err != ErrChannel {
		t.Fatal(err)
	}
	if m.calls != 0 {
		t.Fatal("unauthorized mutation")
	}
	s.uid = 0
	m.fail = true
	if r := exchange(t, s, Request{1, "step", "fixture", 1}); r.Code != "review" {
		t.Fatal(r)
	}
	if r := exchange(t, s, Request{1, "status", "fixture", 0}); r.Phase != "review-required" {
		t.Fatal(r)
	}
	if r := exchange(t, s, Request{1, "step", "fixture", 3}); r.Code != "review" {
		t.Fatal(r)
	}
	if m.calls != 1 {
		t.Fatal("uncertain command repeated")
	}
}

func TestBusyCancellationAndLostReply(t *testing.T) {
	s, m := fixture(t)
	s.uid = 0
	s.mu.Lock()
	if r := exchange(t, s, Request{1, "step", "fixture", 1}); r.Code != "busy" {
		t.Fatal(r)
	}
	s.mu.Unlock()
	server, client := pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- s.Serve(ctx, server) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("blocked read not cancelled")
	}
	client.Close()
	if m.calls != 0 {
		t.Fatal("cancelled input mutated")
	}
	// Disconnect after sending a whole step. It may or may not have committed;
	// reconcile durable state and never assume disconnect rolled it back.
	server, client = pair(t)
	if err := send(client, Request{1, "step", "fixture", 1}); err != nil {
		t.Fatal(err)
	}
	client.Close()
	_ = s.Serve(context.Background(), server)
	r := exchange(t, s, Request{1, "status", "fixture", 0})
	if r.Phase != "group-confirmed" || m.calls != 1 {
		t.Fatal(r, m.calls)
	}
	if r := exchange(t, s, Request{1, "step", "fixture", 1}); r.Code != "conflict" || m.calls != 1 {
		t.Fatal(r)
	}
}

func TestMalformedFramesAndReplies(t *testing.T) {
	for _, data := range []string{
		`{}`, `{"version":1,"Version":1,"action":"status","account_id":"fixture","revision":0}`,
		`{"version":1,"action":"status","account_id":"fixture"}`,
		`{"version":1,"version":1,"action":"status","account_id":"fixture","revision":0}`,
		`{"version":1,"action":"step","account_id":"fixture","revision":0}`,
		`{"version":1,"action":"status","account_id":"../etc","revision":0}`,
		`{"version":1,"action":"shell","account_id":"fixture","revision":1}`,
		`{"version":1,"action":"status","account_id":"fixture","revision":null}`,
		`{"version":1,"action":"status","account_id":"fixture","revision":0,"path":"/etc"}`,
		`{"version":1,"action":"status","account_id":"fixture","revision":0}{}`,
	} {
		var req Request
		if decodeRequest([]byte(data), &req) == nil {
			t.Fatal("accepted", data)
		}
	}
	for _, data := range [][]byte{nil, {0, 0, 0, 0}, {0, 0, 4, 1}, {0, 0, 0, 1}, {0, 0, 0}} {
		if _, err := receive(bytes.NewReader(data)); err == nil {
			t.Fatal(data)
		}
	}
	if err := send(shortWriter{}, Request{1, "status", "fixture", 0}); err != ErrChannel {
		t.Fatal(err)
	}
	for _, r := range []Response{{1, "ok", 1, "unix-confirmed"}, {1, "review", 2, "reserved"}, {2, "ok", 1, "reserved"}, {1, "PRIVATE", 0, ""}} {
		if r.valid() {
			t.Fatal(r)
		}
	}
	if _, err := Call(context.Background(), nil, Request{}); err != ErrChannel {
		t.Fatal(err)
	}
}

type shortWriter struct{}

func (shortWriter) Write(p []byte) (int, error) { return len(p) - 1, nil }

// Real process separation: a root listener talks to a process with UID/GID
// 65534, empty supplementary groups and no inherited channel. No host accounts
// are created; all journal/backend changes stay inside private modeled fixtures.
func TestUnprivilegedClient(t *testing.T) {
	if os.Getenv("PHANTOWD_RPC_CHILD") != "" {
		if os.Geteuid() != 65534 {
			os.Exit(2)
		}
		if os.Getenv("PHANTOWD_RPC_LISTEN") != "" {
			l, err := net.ListenUnix("unix", &net.UnixAddr{Name: os.Getenv("PHANTOWD_RPC_SOCKET"), Net: "unix"})
			if err != nil {
				os.Exit(5)
			}
			defer l.Close()
			os.Stdout.WriteString("ready\n")
			c, err := l.AcceptUnix()
			if err != nil {
				os.Exit(6)
			}
			c.Close()
			os.Exit(0)
		}
		c, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: os.Getenv("PHANTOWD_RPC_SOCKET"), Net: "unix"})
		if err != nil {
			os.Exit(3)
		}
		r, err := Call(context.Background(), c, Request{1, "step", "fixture", 1})
		if err != nil || r.Code != "ok" || r.Phase != "group-confirmed" {
			os.Exit(4)
		}
		os.Exit(0)
	}
	s, m := fixture(t)
	dir, err := os.MkdirTemp("", "rpc-peer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir) // exact test-owned directory, not caller input
	if err := os.Chmod(dir, 0755); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "sock")
	l, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if err := os.Chmod(path, 0666); err != nil {
		t.Fatal(err)
	} // test only
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
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, child, "-test.run=^TestUnprivilegedClient$")
	cmd.Env = []string{"PHANTOWD_RPC_CHILD=1", "PHANTOWD_RPC_SOCKET=" + path, "GORACE=atexit_sleep_ms=0"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534, Groups: []uint32{}}}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer cmd.Process.Kill()
	l.SetDeadline(time.Now().Add(5 * time.Second))
	c, err := l.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Serve(ctx, c); err != nil {
		t.Fatal(err)
	}
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
	if m.calls != 1 {
		t.Fatal(m.calls)
	}
	// A rogue non-root listener cannot impersonate the privileged owner even
	// when the client deliberately connects to its path.
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(dir, 65534, 65534); err != nil {
		t.Fatal(err)
	}
	rogue := exec.CommandContext(ctx, child, "-test.run=^TestUnprivilegedClient$")
	rogue.Env = append(cmd.Env, "PHANTOWD_RPC_LISTEN=1")
	rogue.SysProcAttr = cmd.SysProcAttr
	out, err := rogue.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := rogue.Start(); err != nil {
		t.Fatal(err)
	}
	defer rogue.Process.Kill()
	if line, err := bufio.NewReader(out).ReadString('\n'); err != nil || line != "ready\n" {
		t.Fatal("rogue fixture not ready", err)
	}
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Call(ctx, conn, Request{1, "status", "fixture", 0}); err != ErrChannel {
		t.Fatal("non-root server accepted", err)
	}
	if err := rogue.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestWireRefusals(t *testing.T) {
	s, m := fixture(t)
	s.uid = 0
	server, client := pair(t)
	done := make(chan error, 1)
	go func() { done <- s.Serve(context.Background(), server) }()
	if err := send(client, map[string]string{"shell": "not-a-command"}); err != nil {
		t.Fatal(err)
	}
	data, err := receive(client)
	if err != nil || !bytes.Contains(data, []byte(`"code":"invalid"`)) {
		t.Fatal(string(data), err)
	}
	if err := <-done; err != nil || m.calls != 0 {
		t.Fatal(err)
	}
	server, client = pair(t)
	go func() { done <- s.Serve(context.Background(), server) }()
	client.Write([]byte{0, 0, 4, 1})
	if err := <-done; err != ErrChannel {
		t.Fatal(err)
	}
	server, client = pair(t)
	go func() {
		defer server.Close()
		if _, err := receive(server); err != nil {
			done <- err
			return
		}
		done <- send(server, Response{1, "ok", 1, "unix-confirmed"})
	}()
	if _, err := Call(context.Background(), client, Request{1, "status", "fixture", 0}); err != ErrChannel {
		t.Fatal("bad response accepted")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	s.registry = func() (serviceaccounts.Registry, error) {
		return serviceaccounts.Registry{}, errors.New("PRIVATE registry failure")
	}
	if r := exchange(t, s, Request{1, "step", "fixture", 1}); r.Code != "unavailable" || m.calls != 0 {
		t.Fatal(r)
	}
	s.journal.Close()
	if r := exchange(t, s, Request{1, "status", "fixture", 0}); r.Code != "unavailable" {
		t.Fatal(r)
	}
}

func FuzzRequest(f *testing.F) {
	f.Add([]byte(`{"version":1,"action":"status","account_id":"fixture","revision":0}`))
	f.Add([]byte(`{"version":1,"action":"step","account_id":"fixture","revision":3}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		var r Request
		if err := decodeRequest(data, &r); err == nil && !r.valid() {
			t.Fatal("invalid acceptance")
		}
		var frame bytes.Buffer
		var h [4]byte
		binary.BigEndian.PutUint32(h[:], uint32(len(data)))
		frame.Write(h[:])
		frame.Write(data)
		out, err := receive(&frame)
		if err == nil && (len(out) == 0 || len(out) > maxFrame) {
			t.Fatal("unbounded frame")
		}
	})
}
