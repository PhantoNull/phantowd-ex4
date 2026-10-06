// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package identityrpc

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityprovision"
)

type routedOperation struct {
	journal identityprovision.Journal
	steps   int
	after   func()
}

func (o *routedOperation) Load(context.Context) (identityprovision.Journal, error) {
	return o.journal, nil
}
func (o *routedOperation) Step(ctx context.Context, expected uint64) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if expected != o.journal.Revision {
		return identityprovision.ErrConflict
	}
	switch o.journal.Phase {
	case identityprovision.Reserved:
		o.journal.Phase = identityprovision.GroupConfirmed
	case identityprovision.GroupConfirmed:
		o.journal.Phase = identityprovision.UnixConfirmed
	default:
		return identityprovision.ErrConflict
	}
	o.steps++
	o.journal.Revision += 2
	if o.after != nil {
		o.after()
	}
	return nil
}

func routerFixture(t *testing.T) (*routedOperation, *routedOperation) {
	t.Helper()
	s, _ := fixture(t)
	j, err := s.operation.Load(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	first := &routedOperation{journal: j}
	j.Account.ID = "second"
	j.Account.Name = "rpcsecond"
	j.Account.UID++
	j.Account.GID++
	if err := j.Validate(); err != nil {
		t.Fatal(err)
	}
	return first, &routedOperation{journal: j}
}

func TestRouterIndependentBoundAccounts(t *testing.T) {
	first, second := routerFixture(t)
	lookups := 0
	s, err := NewRouter(65534, func(id string) Operation {
		lookups++
		switch id {
		case "fixture":
			return first
		case "second":
			return second
		case "misbound":
			return first
		default:
			return nil
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	s.uid = 0 // root-only modeled transport test, never a public factory option
	for _, tc := range []struct {
		id, action, code, phase string
		revision, result        uint64
	}{
		{"fixture", "step", "ok", "group-confirmed", 1, 3},
		{"second", "status", "ok", "reserved", 0, 1},
		{"second", "step", "ok", "group-confirmed", 1, 3},
		{"fixture", "step", "conflict", "", 1, 0},
		{"fixture", "step", "ok", "unix-confirmed", 3, 5},
		{"second", "status", "ok", "group-confirmed", 0, 3},
		{"second", "step", "ok", "unix-confirmed", 3, 5},
		{"unknown", "step", "unavailable", "", 1, 0},
		{"misbound", "step", "conflict", "", 5, 0},
	} {
		before := lookups
		reply := exchange(t, s, Request{Version: 1, AccountID: tc.id, Action: tc.action, Revision: tc.revision})
		if lookups != before+1 || reply.Code != tc.code || reply.Phase != tc.phase || reply.Revision != tc.result {
			t.Fatal(tc, reply, lookups, before)
		}
	}
	if first.steps != 2 || second.steps != 2 {
		t.Fatal(first.steps, second.steps)
	}
	if _, err := NewRouter(0, s.resolve); err != ErrInvalid {
		t.Fatal(err)
	}
	if _, err := NewRouter(65534, nil); err != ErrInvalid {
		t.Fatal(err)
	}
}

func TestRouterNoLookupBeforeAuthorizationAndAdmission(t *testing.T) {
	first, _ := routerFixture(t)
	lookups := 0
	s, err := NewRouter(65534, func(string) Operation { lookups++; return first })
	if err != nil {
		t.Fatal(err)
	}
	server, client := pair(t)
	if err := s.Serve(context.Background(), server); err != ErrChannel {
		t.Fatal("unauthorized root peer", err)
	}
	client.Close()
	s.uid = 0
	s.mu.Lock()
	server, client = pair(t)
	if err := s.Serve(context.Background(), server); err != ErrBusy {
		t.Fatal(err)
	}
	client.Close()
	s.mu.Unlock()
	for _, data := range []string{
		`{"version":1,"action":"status","account_id":"../outside","revision":0}`,
		`{"version":1,"action":"reserve","account_id":"fixture","revision":1}`,
	} {
		server, client = pair(t)
		done := make(chan error, 1)
		go func() { done <- s.Serve(context.Background(), server) }()
		frame := append([]byte{0, 0, 0, byte(len(data))}, []byte(data)...)
		if _, err := client.Write(frame); err != nil {
			t.Fatal(err)
		}
		if _, err := receive(client); err != nil {
			t.Fatal(err)
		}
		if err := <-done; err != nil {
			t.Fatal(err)
		}
		client.Close()
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	server, client = pair(t)
	if err := s.Serve(ctx, server); err != ErrChannel {
		t.Fatal(err)
	}
	client.Close()
	if lookups != 0 || first.steps != 0 {
		t.Fatal("unadmitted lookup", lookups, first.steps)
	}
}

func TestRouterPinsOneOperationAndRejectsChangedBinding(t *testing.T) {
	for _, changed := range []bool{false, true} {
		t.Run(map[bool]string{false: "pinned", true: "changed-account"}[changed], func(t *testing.T) {
			first, second := routerFixture(t)
			current := first
			first.after = func() {
				current = second
				if changed {
					first.journal.Account = second.journal.Account
				}
			}
			lookups := 0
			s, err := NewRouter(65534, func(string) Operation { lookups++; return current })
			if err != nil {
				t.Fatal(err)
			}
			s.uid = 0
			r := exchange(t, s, Request{Version: 1, Action: "step", AccountID: "fixture", Revision: 1})
			want := "ok"
			if changed {
				want = "unavailable"
			}
			if r.Code != want || lookups != 1 || first.steps != 1 || second.steps != 0 {
				t.Fatal(r, lookups, first.steps, second.steps)
			}
		})
	}
}

type failedOperation struct{}

func (failedOperation) Load(context.Context) (identityprovision.Journal, error) {
	return identityprovision.Journal{}, errors.New("PRIVATE path detail")
}
func (failedOperation) Step(context.Context, uint64) error { panic("must not dispatch") }

func TestRouterLookupFailureRedacted(t *testing.T) {
	fixture(t) // root test guard
	s, err := NewRouter(65534, func(string) Operation { return failedOperation{} })
	if err != nil {
		t.Fatal(err)
	}
	s.uid = 0
	if r := exchange(t, s, Request{Version: 1, Action: "step", AccountID: "fixture", Revision: 1}); r.Code != "unavailable" || r.Phase != "" || r.Revision != 0 {
		t.Fatal(r)
	}
}

type deliveredReplyGate struct {
	io.ReadWriter
	release <-chan struct{}
}

func (g deliveredReplyGate) Write(p []byte) (int, error) {
	n, err := g.ReadWriter.Write(p)
	// Model the kernel delivering bytes before the writer resumes userspace.
	<-g.release
	return n, err
}

func TestNextRequestAfterDeliveredReply(t *testing.T) {
	s, m := fixture(t)
	s.uid = 0
	server, client := pair(t)
	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- s.serveRequest(context.Background(), deliveredReplyGate{server, release})
		server.Close()
	}()
	defer func() {
		close(release)
		if err := <-done; err != nil {
			t.Error(err)
		}
	}()
	reply, err := Call(context.Background(), client, Request{1, "step", "fixture", 1})
	if err != nil || reply.Phase != identityprovision.GroupConfirmed {
		t.Fatal(reply, err)
	}
	// The client observed the full reply; its NEXT request is not concurrent
	// state work and must not be rejected solely by the prior writer's scheduling.
	second, next := pair(t)
	completed := make(chan error, 1)
	go func() { completed <- s.Serve(context.Background(), second) }()
	reply, err = Call(context.Background(), next, Request{1, "step", "fixture", 3})
	serverErr := <-completed
	if err != nil || serverErr != nil || reply.Phase != identityprovision.UnixConfirmed || m.calls != 2 {
		t.Fatalf("sequential request refused: reply=%+v client=%v server=%v calls=%d", reply, err, serverErr, m.calls)
	}
}
