# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Synthetic boundary receipts only, NOT SMB/Owner/pending-I/O admission.
{ sub(/\r$/, "") }
/^PHANTOWD_PENDING_/ {
    if ($0 == "PHANTOWD_PENDING_LAUNCHER_BOUNDARY_DONE private_namespace=true readonly_root=true caps_zero=true ids_65534=true nnp=true pipe_control=true original_exec=true refusals=3 stopped_reaped=true originals_closed_after_stop=true smb=false scope=qemu-only") boundary++
    else if ($0 == "PHANTOWD_PENDING_LAUNCHER_GUEST_DONE") guest++
    else bad++
}
END { exit (boundary != 1 || guest != 1 || bad != 0) }
