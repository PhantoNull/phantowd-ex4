//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package policytransaction

// Capture the closed fixture plan BEFORE opening any namespace. It is never an
// operation argument, HTTP input or product profile. Only the second operation
// may stop; the first confirmed record must remain outside the selected gate.
func copyHistoryCrash(plan *disposableCrash, policy bool) (*disposableCrash, error) {
	if plan == nil {
		return nil, nil
	}
	if plan.gate == nil || plan.role != "intent" && plan.role != "receipt" && !(policy && plan.role == "policy") {
		return nil, ErrInvalid
	}
	switch plan.point {
	case "partial-write", "full-write", "file-sync", "file-close", "before-rename", "after-rename", "directory-sync":
		owned := *plan
		return &owned, nil
	default:
		return nil, ErrInvalid
	}
}
