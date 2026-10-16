//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

type readinessUnsignaledDeadline struct {
	context.Context
	deadline time.Time
}

func (c readinessUnsignaledDeadline) Deadline() (time.Time, bool) { return c.deadline, true }

func TestReadinessContextChecksOriginalAndDerivedMonotonicDeadlines(t *testing.T) {
	live := context.Background()
	past := readinessUnsignaledDeadline{Context: live, deadline: time.Unix(1, 0)}
	future := readinessUnsignaledDeadline{Context: live, deadline: time.Now().Add(time.Hour)}
	canceled, cancel := context.WithCancel(live)
	cancel()
	for _, tc := range []struct {
		caller, derived context.Context
		want            error
	}{
		{live, future, nil}, {past, live, context.DeadlineExceeded},
		{live, past, context.DeadlineExceeded}, {canceled, future, context.Canceled},
	} {
		if got := readinessContextError(tc.caller, tc.derived); !errors.Is(got, tc.want) {
			t.Fatalf("context guard waited for timer delivery or lost original lifetime: got=%v want=%v", got, tc.want)
		}
	}
}

// Actual owned children and the real Start/rollback seam, not a fabricated
// successful launcher. A probe can observe readiness after its caller cancels
// or its own deadline elapses; that stale result cannot commit a generation.
func TestReadinessCannotCommitAfterContextEnds(t *testing.T) {
	if mode, ok := processOwnerChildMode(os.Args); ok {
		runProcessOwnerChild(t, mode)
		return
	}
	for _, expired := range []bool{false, true} {
		for _, ready := range []bool{false, true} {
			for _, failed := range []bool{false, true} {
				t.Run(fmt.Sprintf("expired=%t/ready=%t/failed=%t", expired, ready, failed), func(t *testing.T) {
					owner := New()
					t.Cleanup(func() { _, _ = owner.Stop(context.Background()) })
					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					private := errors.New("private-readiness-probe-detail")
					probeCalled := false
					budget := 2 * time.Second
					wantCause := context.Canceled
					if expired {
						budget, wantCause = 25*time.Millisecond, context.DeadlineExceeded
					}
					started, err := owner.Start(ctx, Spec{
						Executable: os.Args[0],
						Args:       []string{"-test.run=^TestReadinessCannotCommitAfterContextEnds$", "--", "wait"},
						Ready: func(probe context.Context) (bool, error) {
							probeCalled = true
							if !expired {
								cancel()
							}
							<-probe.Done() // Authoritative cancellation, no scheduling sleep.
							if failed {
								return ready, private
							}
							return ready, nil
						},
						ReadyTimeout: budget, ProbeInterval: 10 * time.Millisecond, StopTimeout: time.Second,
					})
					if !probeCalled || !errors.Is(err, ErrNotReady) || !errors.Is(err, wantCause) ||
						started.State != StateStopped || started.Generation != 0 || started.PID != 0 || owner.current != nil {
						t.Fatalf("late probe committed readiness or lost its context/verified rollback: called=%t snapshot=%+v err=%v", probeCalled, started, err)
					}
					if errors.Is(err, private) || strings.Contains(err.Error(), private.Error()) {
						t.Fatal("readiness refusal disclosed the private probe error")
					}
				})
			}
		}
	}
}
