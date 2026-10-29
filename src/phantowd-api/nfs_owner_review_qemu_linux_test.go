//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestOwnerNFSReviewReportsFailureKindsWithoutCauseText(t *testing.T) {
	for _, tc := range []struct {
		cause error
		want  string
	}{
		{fmt.Errorf("private-cause: %w", context.DeadlineExceeded), "deadline=true canceled=false"},
		{fmt.Errorf("private-cause: %w", context.Canceled), "deadline=false canceled=true"},
		{errors.New("private-cause"), "deadline=false canceled=false"},
	} {
		review := &ownerNFSReview{backend: &ownerNFSQEMU{phase: "policy-update-after-close"}, cause: tc.cause}
		text := review.Error()
		if !strings.Contains(text, "phase=policy-update-after-close") || !strings.Contains(text, tc.want) || strings.Contains(text, "private-cause") {
			t.Fatalf("redacted failure classification differs: %s", text)
		}
		if !errors.Is(review, tc.cause) {
			t.Fatal("classification lost the retained cause")
		}
	}
}

func TestOwnerNFSReviewPreservesSecondLifetimePhase(t *testing.T) {
	inner := &ownerNFSReview{
		backend:     &ownerNFSQEMU{phase: "revision2-start"},
		cause:       fmt.Errorf("private-cause: %w", context.DeadlineExceeded),
		contextDone: true,
	}
	review := &ownerNFSReview{
		backend: &ownerNFSQEMU{phase: "policy-update-after-close"},
		cause:   fmt.Errorf("private-wrapper: %w", inner),
	}
	text := review.Error()
	if !strings.Contains(text, "phase=revision2-start ") ||
		!strings.Contains(text, "deadline=true canceled=false context_done=true") ||
		strings.Contains(text, "policy-update-after-close") || strings.Contains(text, "private-") {
		t.Fatalf("second lifetime failure was masked or disclosed private text: %s", text)
	}
	if !errors.Is(review, context.DeadlineExceeded) || !errors.Is(review, inner) {
		t.Fatal("second lifetime failure lost its original error chain")
	}
}
