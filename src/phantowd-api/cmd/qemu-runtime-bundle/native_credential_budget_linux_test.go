//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
	"time"
)

// The actual native fixture uses this exact timer before construction, after
// original Owner/backend admission and after both journaled enrollments. This
// is accounting evidence only, not modeled passdb or fabricated authority.
func TestNativeCredentialBudgetPreparationCannotSpendEnrollment(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		started := time.Now()
		budget, err := newNativeCredentialBudgetQEMU(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer budget.Close()
		preparation := budget.preparation
		time.Sleep(7 * time.Second)
		enrollment, err := budget.Enrollment(nil)
		if err != nil {
			t.Fatal(err)
		}
		deadline, ok := enrollment.Deadline()
		if !ok || time.Until(deadline) != 60*time.Second {
			t.Errorf("enrollment inherits preparation cost: remaining=%v", time.Until(deadline))
		}
		if preparation.Err() != context.Canceled {
			t.Error("preparation context still live after handoff")
		}
		time.Sleep(55 * time.Second)
		if err := budget.CompleteEnrollment(nil); err != nil {
			t.Errorf("separately bounded enrollment failed at elapsed=%v: %v", time.Since(started), err)
		}
	})
}

func TestNativeCredentialBudgetFailedPreparationNeverEnrollsOrRetries(t *testing.T) {
	uncertain := errors.New("uncertain fixture preparation")
	for _, scenario := range []string{"uncertain", "expired", "canceled", "uncertain-and-expired"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				budget, err := newNativeCredentialBudgetQEMU(parent)
				if err != nil {
					t.Fatal(err)
				}
				defer budget.Close()
				deadline, ok := budget.preparation.Deadline()
				if !ok || time.Until(deadline) != 20*time.Second {
					t.Fatal("preparation lacks its fixed20s bound")
				}
				var prior error
				want := uncertain
				switch scenario {
				case "uncertain":
					prior = uncertain
				case "expired", "uncertain-and-expired":
					time.Sleep(21 * time.Second)
					want = context.DeadlineExceeded
					if scenario == "uncertain-and-expired" {
						prior = uncertain
					}
				case "canceled":
					cancel()
					want = context.Canceled
				}
				enrollment, err := budget.Enrollment(prior)
				if enrollment != nil || !errors.Is(err, want) || budget.enrollment != nil || !budget.closed || budget.preparation.Err() == nil {
					t.Fatal("failed preparation proceeded:", err)
				}
				if prior != nil && !errors.Is(err, prior) {
					t.Fatal("failure erased uncertainty")
				}
				if again, err := budget.Enrollment(nil); again != nil || !errors.Is(err, errNativeCredentialBudgetQEMU) {
					t.Fatal("failed preparation retried")
				}
			})
		})
	}
}

func TestNativeCredentialBudgetParentStillBoundsBothPhases(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		parent, cancel := context.WithTimeout(context.Background(), 35*time.Second)
		defer cancel()
		budget, err := newNativeCredentialBudgetQEMU(parent)
		if err != nil {
			t.Fatal(err)
		}
		defer budget.Close()
		time.Sleep(7 * time.Second)
		enrollment, err := budget.Enrollment(nil)
		if err != nil {
			t.Fatal(err)
		}
		deadline, ok := enrollment.Deadline()
		if !ok || time.Until(deadline) != 28*time.Second {
			t.Fatal("enrollment detached from shorter parent")
		}
		<-enrollment.Done()
		if err := budget.CompleteEnrollment(nil); !errors.Is(err, context.DeadlineExceeded) {
			t.Fatal("late nil erased parent deadline:", err)
		}
	})
}

func TestNativeCredentialBudgetEnrollmentCannotReportLateOrUncertainSuccess(t *testing.T) {
	uncertain := errors.New("uncertain fixture enrollment")
	for _, scenario := range []string{"expired", "uncertain", "uncertain-and-expired", "parent-canceled"} {
		t.Run(scenario, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				parent, cancel := context.WithCancel(context.Background())
				defer cancel()
				budget, err := newNativeCredentialBudgetQEMU(parent)
				if err != nil {
					t.Fatal(err)
				}
				defer budget.Close()
				enrollment, err := budget.Enrollment(nil)
				if err != nil {
					t.Fatal(err)
				}
				var result error
				want := uncertain
				switch scenario {
				case "expired", "uncertain-and-expired":
					time.Sleep(61 * time.Second)
					want = context.DeadlineExceeded
					if scenario == "uncertain-and-expired" {
						result = uncertain
					}
				case "uncertain":
					result = uncertain
				case "parent-canceled":
					cancel()
					want = context.Canceled
				}
				err = budget.CompleteEnrollment(result)
				if !errors.Is(err, want) || !budget.closed || enrollment.Err() == nil {
					t.Fatal("failed enrollment completed:", err)
				}
				if result != nil && !errors.Is(err, result) {
					t.Fatal("completion erased uncertainty")
				}
				if err := budget.CompleteEnrollment(nil); !errors.Is(err, errNativeCredentialBudgetQEMU) {
					t.Fatal("uncertain completion retried")
				}
			})
		})
	}
}

func TestNativeCredentialBudgetSingleHandoffAndClose(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		budget, err := newNativeCredentialBudgetQEMU(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		defer budget.Close()
		enrollment, err := budget.Enrollment(nil)
		if err != nil {
			t.Fatal(err)
		}
		if replacement, err := budget.Enrollment(nil); replacement != nil || !errors.Is(err, errNativeCredentialBudgetQEMU) || enrollment.Err() != nil {
			t.Fatal("duplicate handoff replaced/canceled original timer")
		}
		if err := budget.CompleteEnrollment(nil); err != nil || enrollment.Err() != context.Canceled {
			t.Fatal("completed enrollment did not settle timer:", err)
		}
		if err := budget.CompleteEnrollment(nil); !errors.Is(err, errNativeCredentialBudgetQEMU) {
			t.Fatal("completion retried")
		}
		budget.Close()
		budget.Close()
	})
}

func TestNativeCredentialBudgetInvalidAndClosedInputsRefuse(t *testing.T) {
	uncertain := errors.New("prior uncertainty")
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, parent := range []context.Context{nil, canceled} {
		if budget, err := newNativeCredentialBudgetQEMU(parent); budget != nil || err == nil {
			t.Fatal("invalid/canceled constructor admitted")
		}
	}
	for _, budget := range []*nativeCredentialBudgetQEMU{nil, {}} {
		if ctx, err := budget.Enrollment(uncertain); ctx != nil || !errors.Is(err, errNativeCredentialBudgetQEMU) || !errors.Is(err, uncertain) {
			t.Fatal("invalid handoff admitted or erased uncertainty")
		}
		if err := budget.CompleteEnrollment(uncertain); !errors.Is(err, errNativeCredentialBudgetQEMU) || !errors.Is(err, uncertain) {
			t.Fatal("invalid completion admitted or erased uncertainty")
		}
		budget.Close()
	}
	budget, err := newNativeCredentialBudgetQEMU(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := budget.CompleteEnrollment(nil); !errors.Is(err, errNativeCredentialBudgetQEMU) || budget.preparation.Err() != nil {
		t.Fatal("completion before handoff changed preparation")
	}
	budget.Close()
	if ctx, err := budget.Enrollment(nil); ctx != nil || !errors.Is(err, errNativeCredentialBudgetQEMU) || budget.preparation.Err() != context.Canceled {
		t.Fatal("closed preparation resurrected")
	}
}
