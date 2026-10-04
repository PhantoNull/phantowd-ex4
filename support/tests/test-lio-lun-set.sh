#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Tiny native test of the exact matcher used by the real libiscsi fixture.
set -eu
source_dir=${1:?source checkout required}
temporary=$(mktemp -d /tmp/phantowd-lio-lun-set.XXXXXX)
cleanup() {
    rm -f "$temporary/test"
    rmdir "$temporary"
}
trap cleanup EXIT
trap 'exit 1' INT TERM
cc -std=c11 -Wall -Wextra -Werror -O2 -I"$source_dir/support/fixtures" \
    "$source_dir/support/tests/lio-lun-set-fixture.c" -o "$temporary/test"
"$temporary/test"
