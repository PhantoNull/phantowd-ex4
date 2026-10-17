//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

// constructionReview is an opaque local ownership handle carried by the error
// chain. It exposes no descriptors, retry, close or execution methods. Callers
// MUST retain the original error for the failed service's remaining lifetime;
// logging/replacing the error is not ownership. There is no global quarantine.
// A future product composer must explicitly retain these failed-service errors.
type constructionReview struct {
	constructionreview.Marker
	retained any
	cause    error
}

func (*constructionReview) Error() string        { return "runtime construction requires retained review" }
func (r *constructionReview) Unwrap() error      { return r.cause }
func (*constructionReview) Is(target error) bool { return target == ErrReviewRequired }

func hasConstructionReview(err error) bool {
	return constructionreview.Contains(err)
}

// Only no-child constructors may use this boundary. A nested retained failure
// prohibits further release; otherwise attempt verified rollback exactly once.
// The original cause and first cleanup failure survive normal error wrapping.
func constructionRollback(cause error, retained any, release func() error) error {
	result, hold := constructionreview.Rollback(cause, release)
	if hold {
		return &constructionReview{retained: retained, cause: result}
	}
	return result
}

func (o *Owner) constructionRollback(cause error) error {
	result := constructionRollback(cause, o, o.release)
	var review *constructionReview
	if errors.As(result, &review) {
		o.review = true
		o.snapshot.State = processowner.StateReviewRequired
		// Preserve inner causes, not a cycle from the error back to itself.
		o.releaseErr = review.cause
	}
	return result
}
