#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
set -eu

[ "$#" = 2 ] || exit 1
host_prefix=$1
expected=$2
case "$expected" in ''|*[!0-9.]*) exit 1 ;; esac
printf '%s\n' "$expected" | LC_ALL=C grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$' || exit 1
# Inspect the installed Buildroot host tool, without inherited configuration
# or a library/module search path selecting another installation.
actual=$(env -i PATH=/usr/bin:/bin LC_ALL=C OPENSSL_CONF=/dev/null \
    LD_LIBRARY_PATH="$host_prefix/lib:$host_prefix/lib64" \
    "$host_prefix/bin/openssl" version)
printf '%s\n' "$actual" | LC_ALL=C awk -v expected="$expected" '
    NR == 1 && NF == 11 && $3 ~ /^[0-9][0-9]?$/ &&
        $4 ~ /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)$/ &&
        $5 ~ /^[0-9][0-9][0-9][0-9]$/ &&
        $0 == "OpenSSL " expected " " $3 " " $4 " " $5 \
            " (Library: OpenSSL " expected " " $3 " " $4 " " $5 ")" { valid = 1 }
    END { exit !(NR == 1 && valid) }
' || {
    echo 'Installed OpenSSL does not match the selected host pin' >&2
    exit 1
}
printf 'Selected OpenSSL host tool verified: %s\n' "$actual"
