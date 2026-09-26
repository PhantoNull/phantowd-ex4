// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package identityrpc supplies a one-request local channel to one already
// reserved identity operation. It does not provision listeners or own all writers.
package identityrpc

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/configjson"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/serviceaccounts"
	"golang.org/x/sys/unix"
)

const maxFrame = 1024
const timeout = 10 * time.Second

var (
	ErrChannel = errors.New("identity channel unavailable; reconcile before further action")
	ErrInvalid = errors.New("invalid identity channel request")
	ErrBusy    = errors.New("identity channel admission busy")
)

// Request never contains commands, paths, credentials or caller-selected UID/GID.
// AccountID is the symbolic reservation ID, not a Unix UID.
type Request struct {
	Version   int    `json:"version"`
	Action    string `json:"action"`
	AccountID string `json:"account_id"`
	Revision  uint64 `json:"revision"`
}

// Response contains no raw backend errors or credentials. Only status/ok carry
// a validated journal observation. Other codes require a separate status read.
type Response struct {
	Version  int    `json:"version"`
	Code     string `json:"code"`
	Revision uint64 `json:"revision"`
	Phase    string `json:"phase"`
}

func (r Request) valid() bool {
	if r.Version != 1 || len(r.AccountID) == 0 || len(r.AccountID) > 64 || r.AccountID[0] < 'a' || r.AccountID[0] > 'z' {
		return false
	}
	for _, c := range r.AccountID {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return r.Action == "status" && r.Revision == 0 || r.Action == "step" && r.Revision > 0
}

func (r Response) valid() bool {
	if r.Version != 1 {
		return false
	}
	if r.Code != "ok" {
		switch r.Code {
		case "busy", "conflict", "review", "unavailable", "invalid":
			return r.Revision == 0 && r.Phase == ""
		}
		return false
	}
	return r.Phase == identityprovision.Reserved && r.Revision == 1 ||
		r.Phase == identityprovision.GroupIntent && r.Revision == 2 ||
		r.Phase == identityprovision.GroupConfirmed && r.Revision == 3 ||
		r.Phase == identityprovision.UserIntent && r.Revision == 4 ||
		r.Phase == identityprovision.UnixConfirmed && r.Revision == 5 ||
		r.Phase == identityprovision.ReviewRequired && r.Revision >= 2 && r.Revision <= 6
}

// Server binds trusted in-process dependencies; none comes from the socket.
// Never copy a Server. Its admission lock is NOT global Unix writer ownership.
type Server struct {
	mu        sync.Mutex
	uid       uint32
	operation Operation
}

// Operation is a trusted in-process authority, not socket input. The bound
// owner must serialize its registry and Unix changes inside Step, rechecking
// the expected revision there; Load does not grant an authorization lease.
type Operation interface {
	Load(context.Context) (identityprovision.Journal, error)
	Step(context.Context, uint64) error
}

type journalOperation struct {
	journal  *identityprovision.Store
	registry func() (serviceaccounts.Registry, error)
	backend  identityprovision.Backend
}

func (o journalOperation) Load(context.Context) (identityprovision.Journal, error) {
	return o.journal.Load()
}
func (o journalOperation) Step(ctx context.Context, expected uint64) error {
	r, err := o.registry()
	if err != nil {
		return err
	}
	return o.journal.Step(ctx, expected, r, o.backend)
}

// New requires an already-root owner and a dedicated non-root API UID.
// The caller retains the journal/registry/backend lifetimes and must serialize
// ALL writers externally, including registry changes and other server instances.
func New(apiUID uint32, journal *identityprovision.Store, registry func() (serviceaccounts.Registry, error), backend identityprovision.Backend) (*Server, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || apiUID == 0 || apiUID > 65534 || journal == nil || registry == nil || backend == nil {
		return nil, ErrInvalid
	}
	return NewOperation(apiUID, journalOperation{journal, registry, backend})
}

// NewOperation binds an existing authority-owned operation. It creates neither
// a reservation nor a listener and takes no ownership of the authority lifetime.
func NewOperation(apiUID uint32, operation Operation) (*Server, error) {
	if os.Getuid() != 0 || os.Geteuid() != 0 || apiUID == 0 || apiUID > 65534 || operation == nil {
		return nil, ErrInvalid
	}
	return &Server{uid: apiUID, operation: operation}, nil
}

// Serve owns and always closes one accepted Unix STREAM connection. The
// listener owner must bound accept/goroutine counts and protect its pathname.
// Connection credentials identify the principal, not an HTTP user or executable.
func (s *Server) Serve(ctx context.Context, conn *net.UnixConn) error {
	if conn == nil {
		return ErrChannel
	}
	defer conn.Close()
	if s == nil || s.operation == nil || os.Getuid() != 0 || os.Geteuid() != 0 || ctx == nil || ctx.Err() != nil || !peer(conn, s.uid) {
		return ErrChannel
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil {
		return ErrChannel
	}
	// Admit before reading so slow authenticated clients cannot form a queue.
	if !s.mu.TryLock() {
		// No request was consumed. Closing may reset queued peer data, so a
		// structured reply here cannot be promised. Refuse admission outright.
		return ErrBusy
	}
	defer s.mu.Unlock()
	data, err := receive(conn)
	if err != nil {
		return ErrChannel
	}
	var req Request
	if decodeRequest(data, &req) != nil {
		return send(conn, Response{Version: 1, Code: "invalid"})
	}
	if ctx.Err() != nil {
		return ErrChannel
	}
	return send(conn, s.execute(ctx, req))
}

func (s *Server) execute(ctx context.Context, req Request) Response {
	fail := func(code string) Response { return Response{Version: 1, Code: code} }
	j, err := s.operation.Load(ctx)
	if err != nil || j.Validate() != nil {
		return fail("unavailable")
	}
	if req.AccountID != j.Account.ID {
		return fail("conflict")
	}
	if req.Action == "step" {
		err = s.operation.Step(ctx, req.Revision)
		switch {
		case errors.Is(err, identityprovision.ErrConflict):
			return fail("conflict")
		case errors.Is(err, identityprovision.ErrReview):
			return fail("review")
		case err != nil:
			return fail("unavailable")
		}
		j, err = s.operation.Load(ctx)
		if err != nil || j.Validate() != nil {
			return fail("unavailable")
		}
	}
	return Response{Version: 1, Code: "ok", Revision: j.Revision, Phase: j.Phase}
}

// Call owns/closes one caller-connected Unix STREAM socket, authenticates a
// root peer, and makes exactly one request. No retry or reconnect is attempted.
// Any transport error after dispatch may follow a committed native mutation.
func Call(ctx context.Context, conn *net.UnixConn, req Request) (Response, error) {
	if conn == nil {
		return Response{}, ErrChannel
	}
	defer conn.Close()
	if ctx == nil || ctx.Err() != nil || !req.valid() {
		return Response{}, ErrInvalid
	}
	if !peer(conn, 0) {
		return Response{}, ErrChannel
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if conn.SetDeadline(deadline) != nil || send(conn, req) != nil {
		return Response{}, ErrChannel
	}
	data, err := receive(conn)
	if err != nil {
		return Response{}, ErrChannel
	}
	var reply Response
	if configjson.Decode(bytes.NewReader(data), &reply, maxFrame, 1, map[string]bool{
		"version": true, "code": true, "revision": true, "phase": true,
	}) != nil || !fourFields(data) || !reply.valid() || ctx.Err() != nil {
		return Response{}, ErrChannel
	}
	return reply, nil
}

func decodeRequest(data []byte, req *Request) error {
	if configjson.Decode(bytes.NewReader(data), req, maxFrame, 1, map[string]bool{
		"version": true, "action": true, "account_id": true, "revision": true,
	}) != nil || !fourFields(data) || !req.valid() {
		return ErrInvalid
	}
	return nil
}

func fourFields(data []byte) bool {
	var fields map[string]json.RawMessage
	return json.Unmarshal(data, &fields) == nil && len(fields) == 4
}

func peer(conn *net.UnixConn, uid uint32) bool {
	raw, err := conn.SyscallConn()
	if err != nil {
		return false
	}
	ok := false
	err = raw.Control(func(fd uintptr) {
		kind, err := unix.GetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_TYPE)
		if err != nil || kind != unix.SOCK_STREAM {
			return
		}
		cred, err := unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
		ok = err == nil && cred.Pid > 0 && cred.Uid == uid
	})
	return err == nil && ok
}

func receive(r io.Reader) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, ErrChannel
	}
	n := binary.BigEndian.Uint32(header[:])
	if n == 0 || n > maxFrame {
		return nil, ErrChannel
	}
	data := make([]byte, n)
	if _, err := io.ReadFull(r, data); err != nil {
		return nil, ErrChannel
	}
	return data, nil
}

func send(w io.Writer, value any) error {
	data, err := json.Marshal(value)
	if err != nil || len(data) == 0 || len(data) > maxFrame {
		return ErrChannel
	}
	frame := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(frame, uint32(len(data)))
	copy(frame[4:], data)
	n, err := w.Write(frame)
	if err != nil || n != len(frame) {
		return ErrChannel
	}
	return nil
}
