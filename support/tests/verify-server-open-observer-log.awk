# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if ($0 == "PHANTOWD_SERVER_OPEN_SOURCE_READY refusals=66 dso_refusals=66 real_fd=true real_getters=true synthetic_open=true active_worker=false authority=false scope=qemu-only" && state == 0) { state = 1; next }
    if (wire == 1 && $0 == "PHANTOWD_SERVER_OPEN_WIRE_READY frames=2 c_to_go=true bounded=true synthetic_open=true active_worker=false proof=false scope=qemu-only" && state == 1) { state = 2; next }
    if (wire == 1 && $0 == "PHANTOWD_SERVER_OPEN_PACKET_READY frames=2 kernel_credentials=true original_pair=true synthetic_open=true active_worker=false proof=false scope=qemu-only" && state == 2) { state = 3; next }
    if (wire == 1 && $0 == "PHANTOWD_SERVER_OPEN_REAL_IDS_READY frames=2 real_ids=true effective_ids=false permitted_override=true producer_settled=true active_worker=false proof=false scope=qemu-only" && state == 3) { state = 4; next }
    if ($0 == "PHANTOWD_SERVER_OPEN_SOURCE_GUEST_DONE" && state == (wire == 1 ? 4 : 1)) { state = 5; next }
    failed = 1
}
END { if (failed || state != 5) exit 1 }
