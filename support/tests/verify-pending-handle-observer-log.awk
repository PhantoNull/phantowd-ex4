# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if ($0 == "PHANTOWD_PENDING_HANDLE_SOURCE_READY refusals=36 real_idr=true reused_fnum_distinct=true getters=mocked dso_early_refusals=3 network=false server=false authority=false scope=qemu-only" && state == 0) { state = 1; next }
    if ($0 == "PHANTOWD_PENDING_HANDLE_SOURCE_GUEST_DONE" && state == 1) { state = 2; next }
    failed = 1
}
END { if (failed || state != 2) exit 1 }
