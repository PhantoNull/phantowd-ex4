// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package runtimebundle

import (
	"errors"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/processowner"
)

var ErrReviewRequired = errors.New("runtime code owner requires review")

// OwnerSnapshot is internal evidence, never a network DTO or execution token.
type OwnerSnapshot struct {
	State     processowner.State
	Bundle    Observation
	Processes processowner.SetSnapshot
}

func (OwnerSnapshot) MarshalJSON() ([]byte, error) { return nil, ErrInvalid }
func (*OwnerSnapshot) UnmarshalJSON([]byte) error  { return ErrInvalid }
