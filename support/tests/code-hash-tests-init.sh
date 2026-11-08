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
