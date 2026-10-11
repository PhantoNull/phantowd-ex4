# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_SAMBA_ROOT_STAGE_READY fresh=true hashes_during_copy=true no_overwrite=true refusals=5 scope=qemu-only"
    proof = "PHANTOWD_CAPTURE_RUNTIME_PROOF actual_smbd=true module_retained=true original_channel_pair=true stop_before_release=true existing_passdb_refused=true unchanged_passdb=true fd_equal=true authentication=false file_open=false samples=false authority=false scope=qemu-only"
    done = "PHANTOWD_CAPTURE_RUNTIME_GUEST_DONE"
    tests[1] = "TestServerCaptureClientNoticesRequireCompleteSameOpenSequence"
    tests[2] = "TestServerCaptureClientNoticesRefuseDriftUnrequestedReadsAndOtherProtocols"
    tests[3] = "TestServerCaptureClientDedicatedLifecycleRefusesHostNilCopyCancelBusyAndReview"
    tests[4] = "TestServerCaptureClientConnectionRefusesAbsentCopiedCanceledAndUnstarted"
    tests[5] = "TestServerCaptureClientAccumulatedNoticesNeverLatchPartialOrAcceptUnrequestedRead"
    required = 5
}
{ sub(/\r$/, "") }
/PHANTOWD_/ {
    if (state == 0 && $0 == stage) { state = 1; next }
    if (state == 1 && $0 == proof) { state = 2; next }
    if (state == 2 && $0 == done && completed == required && summary) { state = 3; next }
    refused = 1
}
/^=== RUN/ {
    if (state != 2 || summary || running || completed >= required || $0 != "=== RUN   " tests[completed+1]) { refused = 1; next }
    running = 1
    next
}
/^--- PASS:/ {
    expected = "^--- PASS: " tests[completed+1] " \\([0-9]+(\\.[0-9]+)?s\\)$"
    if (state != 2 || summary || !running || $0 !~ expected) { refused = 1; next }
    completed++
    running = 0
    next
}
/^PASS$/ {
    if (state != 2 || summary || running || completed != required) { refused = 1; next }
    summary = 1
    next
}
/^--- (FAIL|SKIP):|^FAIL($|[ \t])/ { refused = 1 }
/Kernel panic|INTERNAL ERROR|AddressSanitizer|runtime error:/ { refused = 1 }
END { if (state != 3 || completed != required || !summary || running || refused) exit 1 }
