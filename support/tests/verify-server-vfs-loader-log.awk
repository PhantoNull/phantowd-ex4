# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if ($0 == "PHANTOWD_SERVER_VFS_LOADER_READY canonical=true registry=true connect_refused=true loader_refusals=6 uid=65534 caps=0 nnp=true active_worker=false producer=false authority=false scope=qemu-only" && state == 0) { state = 1; next }
    if ($0 == "PHANTOWD_SERVER_VFS_LOADER_GUEST_DONE" && state == 1) { state = 2; next }
    failed = 1
}
END { if (failed || state != 2) exit 1 }
