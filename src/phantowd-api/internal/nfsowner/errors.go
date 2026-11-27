// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package nfsowner

import "errors"

var (
	ErrInvalid        = errors.New("invalid NFS owner")
	ErrReviewRequired = errors.New("NFS owner requires review")
	ErrBusy           = errors.New("NFS owner busy")
	ErrState          = errors.New("NFS owner transition refused")
)
