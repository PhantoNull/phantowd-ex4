#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu
# Generated from fixed builder-owned artifact hashes during image preparation.
# shellcheck source=/dev/null
. /usr/lib/phantowd/qemu-code-hash.env
export TMPDIR=/run
log=/run/code-hash-tests.log
if ! /usr/sbin/phantowd-code-hash-tests -test.v -test.run '^TestCodeHash' >"$log" 2>&1; then
    cat "$log"; exit 1
fi
cat "$log"
if grep -q '^--- SKIP:' "$log"; then exit 1; fi
for name in ReaderRetainsOriginalInputs ReaderRefusesChangedFile FrameAllOrError \
    ReaderCanceledBeforeReadDoesNotConsume ReaderRefusesUnsafeInputs \
    ReaderChildRefusalsAreSticky ReaderUncertainCloseNeverRetriesOrConsumesCallerInputs \
    ReaderRefusesUnadmittedProgram; do
    grep -Eq "^--- PASS: TestCodeHash$name \(" "$log" || exit 1
done
echo 'PHANTOWD_SAMBA_ROOT_CODE_HASH_READY fixed_program=true inherited_ro_files=true bytes=true refusals=true canceled=true settled=true scope=qemu-only'
log=/run/code-owner-tests.log
if ! /usr/sbin/phantowd-code-owner-tests -test.v -test.run '^TestHashedOwner' >"$log" 2>&1; then
    cat "$log"; exit 1
fi
cat "$log"
if grep -Eq '^[[:space:]]*--- SKIP:' "$log"; then exit 1; fi
for name in RefusesAdmittedBrokenReaderBeforeServiceStart \
    RunsAfterCallerCloseAndStopsOnCanceledClose \
    StopsOnChangedBytesOrSameBytesReplacement StopsOnChangedDeclaredAlias \
    DeadlineStopsBeforeServiceAndRetainsReview StopsOnOriginalProgramChange \
    ReleaseFaultKeepsRemainingAuthorityWithoutRetry \
    ConcurrentCloseCannotReleaseOriginalRoot; do
    grep -Eq "^--- PASS: TestHashedOwner$name \(" "$log" || exit 1
done
echo 'PHANTOWD_SAMBA_ROOT_CODE_OWNER_READY normal_owner=true start_stop=true drift_refused=true cancellation=true review_sticky=true scope=qemu-only'
