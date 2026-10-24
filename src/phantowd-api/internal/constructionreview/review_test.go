// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package constructionreview

import (
	"errors"
	"fmt"
	"testing"
)

type fixtureHandle struct {
	Marker
	cause error
}

func (*fixtureHandle) Error() string   { return "fixture retained construction" }
func (h *fixtureHandle) Unwrap() error { return h.cause }

func TestRollbackPreservesCausesWithoutMistakingPlainReviewForOwnership(t *testing.T) {
	cause, cleanup := errors.New("construction cause"), errors.New("cleanup cause")
	called := 0
	result, retained := Rollback(cause, func() error { called++; return nil })
	if result != cause || retained || called != 1 {
		t.Fatal("verified rollback changed the original cause or retained a lifetime")
	}
	result, retained = Rollback(cause, func() error { called++; return cleanup })
	if !retained || !errors.Is(result, cause) || !errors.Is(result, cleanup) || called != 2 {
		t.Fatal("uncertain rollback lost a cause or retried cleanup")
	}
	if Contains(result) || Contains(errors.New("process construction requires retained review")) {
		t.Fatal("plain errors were mistaken for retained ownership")
	}
	inner := &fixtureHandle{cause: result}
	wrapped := errors.Join(errors.New("another branch"), fmt.Errorf("composition: %w", inner))
	result, retained = Rollback(wrapped, func() error { t.Fatal("nested retained failure continued cleanup"); return nil })
	if result != wrapped || !retained || !Contains(result) || !errors.Is(result, cleanup) {
		t.Fatal("nested opaque lifetime was not preserved through error wrapping")
	}
	if result, retained := Rollback(nil, func() error { t.Fatal("successful construction was released"); return nil }); result != nil || retained {
		t.Fatal("successful construction acquired an error handle")
	}
}

func TestMissingReleaseRetainsCauseWithoutPanic(t *testing.T) {
	cause := errors.New("construction cause")
	if result, retained := Rollback(cause, nil); result != cause || !retained {
		t.Fatal("missing cleanup lost the original cause or claimed safe release")
	}
}
