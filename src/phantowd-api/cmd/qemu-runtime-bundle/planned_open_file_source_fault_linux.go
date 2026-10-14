//go:build qemu && linux

// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors

package main

import (
	"context"

	"github.com/PhantoNull/phantowd-ex4/phantowd-api/identityowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/mountowner"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/runtimebundle"
	"github.com/PhantoNull/phantowd-ex4/phantowd-api/internal/smbexec"
)

const plannedFileSourceFaultMarkerQEMU = "PHANTOWD_SAMBA_OWNER_PLANNED_FILE_SOURCE_FAULT_READY same_authorities=true same_daemon=true data_verified=true original_object=true original_open=true client_daemon_stopped=true original_file_retained=true old_observers_refused=true source_covered=true exclusive_supervision=true review_sticky=true private_inputs=15 runtime_inputs_retained=true originals_busy=true cover_removed=true restoration_refused=true close_refused=true private_mount_namespace=true subprocess_disposal=true parent_fd_equal=true activation=false scope=qemu-only"

const plannedFileSourceFaultChildProofQEMU = "PHANTOWD_PLANNED_FILE_SOURCE_FAULT_CHILD_READY same_authorities=true same_daemon=true data_verified=true original_object=true original_open=true client_daemon_stopped=true original_file_retained=true old_observers_refused=true source_covered=true exclusive_supervision=true review_sticky=true private_inputs=15 runtime_inputs_retained=true originals_busy=true cover_removed=true restoration_refused=true close_refused=true private_mount_namespace=true scope=qemu-subprocess-only\n"

func nativePlannedFileSourceFaultQEMU() error {
	return nativePlannedFaultQEMU("file-source")
}

func qualifyPlannedFileSourceFaultQEMU(ctx context.Context, service *smbexec.NativePlannedServiceQEMU, native *runtimebundle.NativeSambaRuntimeQEMU, owner *identityowner.Owner, handoff *mountowner.ServiceHandoff) error {
	return qualifyPlannedHeldSourceFaultQEMU(ctx, service, native, owner, handoff, true)
}
