# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Complete input retention only, NOT process/SMB/pending-I/O admission.
{ sub(/\r$/, "") }
/^PHANTOWD_PENDING_/ {
    if ($0 == "PHANTOWD_PENDING_INPUTS_READY complete_root=true complete_bootstrap=true fixed_documents=true original_pins=true caller_duplicate_closed=true late_rechecked=true mismatches=2 canceled_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only" && phase == 0) { ready++; phase = 1 }
    else if ($0 == "PHANTOWD_PENDING_OWNER_READY complete_inputs=true adapter_bound=true constructor_refused=true caller_duplicate_closed=true late_rechecked=true copied_refused=true canceled_refused=true busy_refused=true released_refused=true no_fd_leak=true execution=false scope=qemu-only" && phase == 1) { owner++; phase = 2 }
    else if ($0 == "PHANTOWD_PENDING_OWNER_INPUT_LOSS_READY real_constructor=true never_started=true lost_pin_closed=true close_refused=true review_retained=true unattempted_retained=true repeated_refused=true cause_preserved=true review_fd_count_equal=true unrelated_kept=true client_executed=false scope=qemu-only" && phase == 2) { loss++; phase = 3 }
    else if ($0 == "PHANTOWD_PENDING_OWNER_INPUT_LOSS_PROCESS_READY exit0=true child_reaped=true parent_fd_count_equal=true client_executed=false scope=qemu-only" && phase == 3) { disposed++; phase = 4 }
    else if ($0 == "PHANTOWD_PENDING_INPUTS_GUEST_DONE" && phase == 4) { guest++; phase = 5 }
    else bad++
}
END { exit (ready != 1 || owner != 1 || loss != 1 || disposed != 1 || guest != 1 || bad != 0 || phase != 5) }
