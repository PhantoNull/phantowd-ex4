//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import (
	"os"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/constructionreview"
)

// No methods expose the retained failed object, descriptors or retry authority.
// Callers must own this original error chain, not merely its formatted message.
type constructionFailure struct {
	constructionreview.Marker
	retained any
	cause    error
}

func (*constructionFailure) Error() string        { return "process construction requires retained review" }
func (r *constructionFailure) Unwrap() error      { return r.cause }
func (*constructionFailure) Is(target error) bool { return target == ErrReviewRequired }

func constructionRollback(cause error, retained any, release func() error) error {
	result, hold := constructionreview.Rollback(cause, release)
	if hold {
		return &constructionFailure{retained: retained, cause: result}
	}
	return result
}

func (s *PinnedSet) constructionRollback(cause error) error {
	result := constructionRollback(cause, s, s.release)
	if review, ok := result.(*constructionFailure); ok {
		s.closed = true
		s.releaseErr = review.cause
		s.set.reviewRequired = true
		s.set.state = StateReviewRequired
	}
	return result
}

// No child exists in capture constructors, including their fixed fixture ABIs.
// Preserve later originals at the first uncertain close; live teardown is separate.
func (c *CaptureOwner) constructionRollback(cause error) error {
	result := constructionRollback(cause, c, func() error {
		for _, slot := range []**os.File{&c.executable, &c.input} {
			if *slot != nil {
				if err := (*slot).Close(); err != nil {
					return err
				}
				*slot = nil
			}
		}
		for len(c.fixtureInputs) > 0 {
			if err := c.fixtureInputs[0].Close(); err != nil {
				return err
			}
			c.fixtureInputs[0] = nil
			c.fixtureInputs = c.fixtureInputs[1:]
		}
		c.fixtureInputsValid = nil
		return nil
	})
	if review, ok := result.(*constructionFailure); ok {
		c.closed, c.review, c.closeFailed = true, true, true
		c.constructionErr = review.cause
	}
	return result
}
