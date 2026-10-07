//go:build linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package smbexec

import "time"

// No profile or duration is accepted from HTTP, RPC, policy or account input.
// Only the compile-tagged native fixture selects the second fixed profile.
type revocationProfile uint8

const (
	commandRevocationProfile revocationProfile = iota + 1
	nativeQEMURevocationProfile
)

type revocationLimits struct {
	total, status, control time.Duration
}

func (profile revocationProfile) limits() (revocationLimits, bool) {
	switch profile {
	case commandRevocationProfile:
		return revocationLimits{sessionRevocationTimeout, sessionStatusTimeout, sessionRevocationTimeout}, true
	case nativeQEMURevocationProfile:
		worker := 2 * sessionStatusTimeout
		// One initial inventory, one control and two absence inventories:
		// four complete workers, plus one worker-sized margin for bounded
		// parsing/polling. Status/control stay capped at four seconds each;
		// the fixed twenty-second total never permits a control retry.
		return revocationLimits{time.Duration(3+stableAbsentSessionInventories) * worker, worker, worker}, true
	default:
		return revocationLimits{}, false
	}
}
