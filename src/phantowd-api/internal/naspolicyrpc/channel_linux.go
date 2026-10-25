//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package naspolicyrpc provides a retained local desired-policy channel, not
// service activation. It borrows the original Owner; it never opens state,
// releases consumer leases, closes the parent, reconnects or retries.
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
	"sync/atomic"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicy"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/naspolicystore"
	"golang.org/x/sys/unix"
)

const budget = 5 * time.Second
const maxFrame = 10 + naspolicy.MaxInputBytes

// Private wire v1: uint32 BE frame length, version byte, action/status byte,
// uint64 BE revision, then optional strictly decoded complete policy JSON.
// Request actions: 1 snapshot, 2 commit. Status indexes name only fixed errors.
var statuses = [...]error{nil, naspolicystore.ErrBusy, naspolicystore.ErrConflict,
	naspolicystore.ErrInvalid, naspolicystore.ErrReview, naspolicystore.ErrClosed}

type Server struct {
	self  *Server
	owner *naspolicystore.Owner
	uid   uint32
	used  atomic.Bool
}

func NewServer(owner *naspolicystore.Owner, apiUID uint32) (*Server, error) {
	if owner == nil || os.Getuid() != 0 || os.Geteuid() != 0 || apiUID == 0 || apiUID > 65534 {
		return nil, naspolicystore.ErrInvalid
	}
	s := &Server{owner: owner, uid: apiUID}
	s.self = s
	return s, nil
}

// Serve consumes one already-connected Unix stream once, admitting the kernel
// peer before reading bytes. Credentials identify a UID, not an executable.
func (s *Server) Serve(ctx context.Context, conn *net.UnixConn) error {
	if s == nil || s.self != s || ctx == nil || conn == nil || !s.used.CompareAndSwap(false, true) {
		return naspolicystore.ErrInvalid
	}
	if !peer(conn, s.uid) {
		conn.Close()
		return naspolicystore.ErrInvalid
	}
	return serve(ctx, conn, s.owner)
}

func serve(ctx context.Context, conn net.Conn, owner *naspolicystore.Owner) error {
	defer conn.Close()
	joined := interrupt(ctx, conn)
	defer joined()
	for {
		// Idle is bounded by the service lifetime, not the operation budget.
		conn.SetDeadline(time.Time{})
		if ctx.Err() != nil {
			return naspolicystore.ErrReview
		}
		var first [1]byte
		if _, err := io.ReadFull(conn, first[:]); err != nil {
			return naspolicystore.ErrReview
		}
		op, cancel := context.WithTimeout(ctx, budget)
		deadline, _ := op.Deadline()
		conn.SetDeadline(deadline)
		request, err := readFrame(io.MultiReader(bytes.NewReader(first[:]), conn))
		if err != nil {
			cancel()
			return naspolicystore.ErrReview
		}
		response := dispatch(op, owner, request)
		err = writeFrame(conn, response)
		cancel()
		if err != nil || response[1] >= 4 {
			return naspolicystore.ErrReview
		}
	}
}

func dispatch(ctx context.Context, owner *naspolicystore.Owner, request []byte) []byte {
	var err error = naspolicystore.ErrInvalid
	var revision uint64
	var payload []byte
	if len(request) >= 10 && request[0] == 1 {
		expected := binary.BigEndian.Uint64(request[2:10])
		if request[1] == 1 && expected == 0 && len(request) == 10 {
			var c naspolicy.Config
			c, err = owner.Snapshot(ctx)
			if err == nil {
				revision = c.Revision
				payload, err = json.Marshal(c)
			}
		} else if request[1] == 2 && expected > 0 && expected != ^uint64(0) {
			c, decodeErr := naspolicy.Decode(bytes.NewReader(request[10:]))
			if decodeErr == nil && c.Revision == expected+1 {
				err = owner.Commit(ctx, expected, c)
				if err == nil {
					revision = c.Revision
				}
			}
		}
	}
	if err == nil {
		return message(0, revision, payload)
	}
	code := byte(4)
	for i := 1; i < len(statuses); i++ {
		if errors.Is(err, statuses[i]) {
			code = byte(i)
			break
		}
	}
	return message(code, 0, nil)
}

func message(code byte, revision uint64, payload []byte) []byte {
	b := make([]byte, 10+len(payload))
	b[0], b[1] = 1, code
	binary.BigEndian.PutUint64(b[2:10], revision)
	copy(b[10:], payload)
	return b
}

func readFrame(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(header[:])
	if n < 10 || n > maxFrame {
		return nil, naspolicystore.ErrInvalid
	}
	data := make([]byte, n)
	_, err := io.ReadFull(r, data)
	return data, err
}

func writeFrame(w io.Writer, data []byte) error {
	if len(data) < 10 || len(data) > maxFrame {
		return naspolicystore.ErrInvalid
	}
	b := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(b, uint32(len(data)))
	copy(b[4:], data)
	n, err := w.Write(b)
	if err == nil && n != len(b) {
		err = io.ErrShortWrite
	}
	return err
}

func interrupt(ctx context.Context, conn net.Conn) func() {
	done := make(chan struct{})
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()); close(done) })
	return func() {
		if !stop() {
			<-done
		}
	}
}

func peer(conn *net.UnixConn, uid uint32) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	err = raw.Control(func(fd uintptr) {
		kind, e := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		cred, e2 := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		ok = e == nil && e2 == nil && kind == unix.SOCK_STREAM && cred.Pid > 0 && cred.Uid == uid
	})
	return err == nil && ok
}
