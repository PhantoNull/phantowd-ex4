# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if ($0 == "PHANTOWD_SERVER_OPEN_SOURCE_READY refusals=65 dso_refusals=65 real_fd=true real_getters=true synthetic_open=true active_worker=false authority=false scope=qemu-only" && state == 0) { state = 1; next }
    if (wire == 1 && $0 == "PHANTOWD_SERVER_OPEN_WIRE_READY frames=2 c_to_go=true bounded=true synthetic_open=true active_worker=false proof=false scope=qemu-only" && state == 1) { state = 2; next }
    if ($0 == "PHANTOWD_SERVER_OPEN_SOURCE_GUEST_DONE" && state == (wire == 1 ? 2 : 1)) { state = 3; next }
    failed = 1
}
END { if (failed || state != 3) exit 1 }
