#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Extend only the existing service guest; no additional VM or product startup.
set -eu
[ "$#" -eq 7 ] || exit 1
target=$1 go_binary=$2 compiler=$3 debugfs=$4 source_dir=$5 scratch=$6 image=$7
helper="$target/usr/sbin/phantowd-code-hash"
if [ ! -f "$helper" ] || [ -L "$helper" ]; then
    echo 'Code hash tests require the built package artifact' >&2; exit 1
fi
directory="$scratch/code-hash"
mkdir "$directory"
(cd "$source_dir/src/phantowd-api" && CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=5 \
    "$go_binary" test -c -trimpath -o "$directory/tests" ./internal/processowner)
printf '%s\n' 'export PHANTOWD_CODE_HASH_TEST_HELPER=/usr/sbin/phantowd-code-hash' > "$directory/environment"
for index in 0 1 2 3 4; do
    binary=$helper
    if [ "$index" -ne 0 ]; then
        binary="$directory/refusal-$index"
        "$compiler" -static -std=c11 -O2 -Wall -Wextra -Werror \
            -DFIXTURE_CASE="$index" "$source_dir/support/tests/code-hash-refusal-fixture.c" -o "$binary"
        sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" "$image" "$binary" \
            "/usr/sbin/phantowd-code-hash-refusal-$index" "$scratch/hash-roundtrip" 0100755
    fi
    digest=$(sha256sum "$binary" | awk '{print $1}')
    printf 'export PHANTOWD_CODE_HASH_TEST_SHA256_%s=%s\n' "$index" "$digest" >> "$directory/environment"
done
for pair in "$directory/tests phantowd-code-hash-tests" \
    "$source_dir/support/tests/code-hash-tests-init.sh phantowd-code-hash-tests-init"; do
    sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" "$image" \
        "${pair%% *}" "/usr/sbin/${pair#* }" "$scratch/hash-roundtrip" 0100755
done
sh "$source_dir/support/tests/stage-samba-root-file.sh" "$debugfs" "$image" \
    "$directory/environment" /usr/lib/phantowd/qemu-code-hash.env "$scratch/hash-roundtrip" 0100644
