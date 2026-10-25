//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package naspolicyrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/fileservice"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/iscsipolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/nfsconfig"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/shareconfig"
	"golang.org/x/sys/unix"
)

func pair(t *testing.T) (*net.UnixConn, *net.UnixConn) {
	t.Helper()
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_STREAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		t.Fatal(err)
	}
	convert := func(fd int) *net.UnixConn {
		f := os.NewFile(uintptr(fd), "policy-test")
		c, err := net.FileConn(f)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { c.Close() })
		return c.(*net.UnixConn)
	}
	return convert(fds[0]), convert(fds[1])
}

func exchange(t *testing.T, c net.Conn, action byte, expected uint64, payload []byte) []byte {
	t.Helper()
	c.SetDeadline(time.Now().Add(time.Second))
	if err := writeFrame(c, message(action, expected, payload)); err != nil {
		t.Fatal(err)
	}
	reply, err := readFrame(c)
	if err != nil || reply[0] != 1 {
		t.Fatal(reply, err)
	}
	return reply
}

func policy(r uint64) naspolicy.Config {
	return naspolicy.Config{Format: naspolicy.Format, SchemaVersion: 1, Revision: r,
		FileServices: fileservice.Config{Format: fileservice.ConfigFormat, SchemaVersion: 1, Revision: r,
			Shares: shareconfig.Config{Format: shareconfig.Format, SchemaVersion: 1, Revision: r,
				Volumes: []shareconfig.Volume{}, Users: []shareconfig.User{}, Shares: []shareconfig.Share{}},
			NFS: nfsconfig.Policy{Format: nfsconfig.Format, SchemaVersion: 1, Revision: r, VolumeRevision: r, Exports: []nfsconfig.Export{}}},
		ISCSI: iscsipolicy.Policy{Format: iscsipolicy.Format, SchemaVersion: 1, Revision: r, VolumeRevision: r,
			Backings: []iscsipolicy.Backing{}, Targets: []iscsipolicy.Target{}}}
}

func TestOriginalOwnerTransactionsAcrossRetainedChannel(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	s, err := naspolicystore.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Commit(0, policy(1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	o, err := naspolicystore.OpenOwner(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if os.Geteuid() != 0 {
		if _, err := NewServer(o, uint32(os.Getuid())); !errors.Is(err, naspolicystore.ErrInvalid) {
			t.Fatal("non-root constructor", err)
		}
	}
	a, b := pair(t)
	// Host seam bypasses ONLY the root constructor, not peer admission or I/O.
	server := &Server{owner: o, uid: uint32(os.Getuid())}
	server.self = server
	done := make(chan struct{})
	go func() { server.Serve(ctx, b); close(done) }()
	defer func() { a.Close(); <-done }()
	read := func() naspolicy.Config {
		reply := exchange(t, a, 1, 0, nil)
		got, err := naspolicy.Decode(bytes.NewReader(reply[10:]))
		if err != nil || reply[1] != 0 || binary.BigEndian.Uint64(reply[2:10]) != got.Revision {
			t.Fatal(reply, err)
		}
		return got
	}
	commit := func(expected uint64, status byte) {
		payload, _ := json.Marshal(policy(2))
		reply := exchange(t, a, 2, expected, payload)
		if reply[1] != status || len(reply) != 10 {
			t.Fatal(reply)
		}
	}
	if read().Revision != 1 {
		t.Fatal("initial snapshot")
	}
	for _, bad := range [][]byte{message(9, 0, nil), message(1, 1, nil), message(2, 1, []byte("{")), message(1, 0, []byte("extra"))} {
		if writeFrame(a, bad) != nil {
			t.Fatal("send invalid request")
		}
		reply, err := readFrame(a)
		if err != nil || reply[1] != 3 || len(reply) != 10 {
			t.Fatal(reply, err)
		}
	}
	lease, err := o.Acquire(ctx, 1)
	if err != nil {
		t.Fatal(err)
	}
	commit(1, 1)
	if err := lease.Verify(ctx); err != nil {
		t.Fatal(err)
	}
	if err := lease.Release(); err != nil {
		t.Fatal(err)
	}
	commit(1, 0)
	commit(1, 2)
	got, err := o.Snapshot(ctx)
	if err != nil || got.Revision != 2 {
		t.Fatal(got, err)
	}
	if read().Revision != 2 {
		t.Fatal("saved snapshot")
	}
	a.Close()
	<-done
	if got, err := o.Snapshot(ctx); err != nil || got.Revision != 2 {
		t.Fatal("channel closed parent Owner", err)
	}
}

func TestPeerRefusalAndCanceledIdleDoNotReadState(t *testing.T) {
	a, b := pair(t)
	s := &Server{uid: uint32(os.Getuid()) + 1}
	s.self = s
	if err := s.Serve(context.Background(), b); !errors.Is(err, naspolicystore.ErrInvalid) {
		t.Fatal(err)
	}
	if _, err := NewServer(nil, 0); !errors.Is(err, naspolicystore.ErrInvalid) {
		t.Fatal(err)
	}
	a.Close()
	a, b = pair(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- serve(ctx, b, nil) }()
	select {
	case err := <-done:
		if !errors.Is(err, naspolicystore.ErrReview) {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled idle read hung")
	}
}

func TestFrameBoundsAndPartialReadRefuse(t *testing.T) {
	for _, size := range []uint32{0, 9, maxFrame + 1, 10} {
		var header [4]byte
		binary.BigEndian.PutUint32(header[:], size)
		if _, err := readFrame(bytes.NewReader(header[:])); err == nil {
			t.Fatal(size)
		}
	}
	for _, payload := range [][]byte{make([]byte, 9), make([]byte, maxFrame+1)} {
		if err := writeFrame(io.Discard, payload); err == nil {
			t.Fatal("invalid output frame accepted")
		}
	}
}
