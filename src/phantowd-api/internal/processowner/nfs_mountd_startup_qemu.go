//go:build qemu

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package processowner

import "bytes"

const nfsMountdHandoffQEMU = "PHANTOWD_NFS_MOUNTD_HANDOFF private_view=true capabilities_zero=true channels=3 active_interfaces=lo fixed_mountd=true\n"
const nfsMountdStartupQEMU = nfsMountdHandoffQEMU + "rpc.mountd: Version 2.8.6 starting\n"

// NFSMountdStartupReadyQEMU recognizes only the fixed fixture startup stream.
// A prefix is pending within the ORIGINAL readiness deadline, not a whitelist
// or success. Any unexpected/trailing byte refuses. No I/O or authority here.
func NFSMountdStartupReadyQEMU(data []byte) (bool, error) {
	if !bytes.HasPrefix([]byte(nfsMountdStartupQEMU), data) {
		return false, ErrInvalid
	}
	return len(data) == len(nfsMountdStartupQEMU), nil
}
