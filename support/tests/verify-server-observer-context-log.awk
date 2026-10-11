# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    proof = "PHANTOWD_SERVER_OBSERVER_CONTEXT_PROOF original_sender=true kernel_child_credentials=true sole_endpoint=true isolated_root=true original_inputs_after_stop=true scope=qemu-only"
    done = "PHANTOWD_SERVER_OBSERVER_CONTEXT_GUEST_DONE"
}
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if (state == 0 && $0 == proof) { state = 1; next }
    if (state == 1 && $0 == done) { state = 2; next }
    refused = 1
}
END { if (state != 2 || refused) exit 1 }
