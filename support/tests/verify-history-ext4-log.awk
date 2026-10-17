# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
BEGIN {
    stage = "PHANTOWD_HISTORY_EXT4_PREPARED synthetic_ext4=true snapshot=true stages=21 admission=false scope=qemu-only"
    done = "PHANTOWD_HISTORY_EXT4_DONE sigkill=21 original_refs=true first_record_preserved=true runtime_reader=true pending_review=true review=true loss_observer_readonly=true process_boundary=true normal_unmount=true scope=qemu-only"
    expected[++required] = "TestHistoryExt4RemountRejectsUnlinkedReadPin"
    expected[++required] = "TestRuntimeHistoryWriterOnExt4"
    split("normal readonly full process-boundary", cases, " ")
    for (i = 1; i <= 4; i++) expected[++required] = "TestRuntimeHistoryWriterOnExt4/" cases[i]
    expected[++required] = "TestRuntimeHistoryObserverAfterExt4ProcessLoss"
    split("intent policy receipt", roles, " ")
    split("partial-write full-write file-sync file-close before-rename after-rename directory-sync", points, " ")
    for (r = 1; r <= 3; r++) {
        for (i = 1; i <= 7; i++) expected[++required] = "TestRuntimeHistoryObserverAfterExt4ProcessLoss/" roles[r] "/" points[i]
    }
    if (selection == 1) {
        expression = "^("; separator = ""
        for (i = 1; i <= required; i++) {
            if (index(expected[i], "/") == 0) {
                expression = expression separator expected[i]; separator = "|"
            }
        }
        print expression ")$"
        exit
    }
}
{ sub(/\r$/, "") }
/^[ \t]*--- PASS: / {
    name = $0
    sub(/^[ \t]*--- PASS: /, "", name)
    if (!sub(/ \([0-9]+(\.[0-9]+)?s\)$/, "", name) || state != 1 || name != expected[++passed]) refused = 1
    next
}
/^PASS$/ {
    if (state == 1 && passed == required) state = 2
    else refused = 1
    next
}
/PHANTOWD_/ {
    if (state == 0 && $0 == stage) { state = 1; next }
    if (state == 2 && $0 == done) { state = 3; next }
    refused = 1
}
/--- (FAIL|SKIP):|^FAIL$|testing: warning: no tests to run|Kernel panic|INTERNAL ERROR|AddressSanitizer|runtime error:|WARNING: DATA RACE/ { refused = 1 }
END {
    if (selection == 1) exit 0
    if (state != 3 || passed != required || refused) exit 1
}
