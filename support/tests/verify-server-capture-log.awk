# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN { ready = "PHANTOWD_SERVER_CAPTURE_READY sync=true async=true paired_frames=true credentials=true cases=20 sticky_refusal=true unchanged_data=true fd_equal=true uid=65534 caps=0 nnp=true synthetic_open=true active_worker=false authority=false scope=qemu-only" }
{
    sub(/\r$/, "")
    if ($0 ~ /PHANTOWD|PANIC|INTERNAL ERROR/) {
        if (step == 0 && $0 == ready) { step = 1; next }
        if (step == 1 && $0 == "PHANTOWD_SERVER_CAPTURE_GUEST_DONE") { step = 2; next }
        bad = 1
    }
}
END { if (bad || step != 2) exit 1 }
