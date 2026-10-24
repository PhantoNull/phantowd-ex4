// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

// Package constructionreview coordinates no-child rollback classification
// without importing service owners. It is not execution or recovery authority.
package constructionreview

import "errors"

// Marker is embedded by package-private error handles that actually retain
// their failed lifetime and causes. It is classification, not proof of ownership
// or an admission token. Domains keep their own opaque objects and sentinels.
type Marker struct{}

func (Marker) retainedConstructionReview() {}

// Contains recognizes retained construction errors through ordinary wrapping,
// including across domains. Matching a plain review sentinel is insufficient.
func Contains(err error) bool {
	var marker interface{ retainedConstructionReview() }
	return errors.As(err, &marker)
}

// Rollback is for trusted constructors with no child. A missing release callback
// conservatively retains the original cause without attempting cleanup.
// On retained=true the caller MUST wrap result in a local opaque handle retaining
// its own unattempted objects. Nested retained failures prohibit further cleanup.
// Otherwise verified rollback preserves the original error object unchanged.
func Rollback(cause error, release func() error) (result error, retained bool) {
	if cause == nil {
		return nil, false
	}
	if Contains(cause) || release == nil {
		return cause, true
	}
	if closeErr := release(); closeErr != nil {
		return errors.Join(cause, closeErr), true
	}
	return cause, false
}
