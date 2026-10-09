# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Complete input retention only, NOT process/SMB/pending-I/O admission.
{ sub(/\r$/, "") }
/^PHANTOWD_PENDING_/ {
    if ($0 == "PHANTOWD_PENDING_INPUTS_READY complete_root=true complete_bootstrap=true fixed_documents=true original_pins=true caller_duplicate_closed=true late_rechecked=true mismatches=2 canceled_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only") ready++
    else if ($0 == "PHANTOWD_PENDING_INPUTS_GUEST_DONE") guest++
    else bad++
}
END { exit (ready != 1 || guest != 1 || bad != 0) }
