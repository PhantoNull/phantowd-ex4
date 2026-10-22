#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Incremental experiment in RAM; never modify the persistent SDK workspace.
set -eu
[ "$#" -eq 3 ] || exit 1
cached=$1 shadow=$2 patch_file=$3
case "$cached:$shadow:$patch_file" in *[!a-zA-Z0-9_./:-]*) exit 1 ;; esac
[ "$(realpath -e "$shadow")" = "$shadow" ] || exit 1
awk -v target="$shadow" '$2 == target && $3 == "tmpfs" { good=1 } END { exit !good }' /proc/mounts || exit 1
[ -f "$cached/source3/utils/status.c" ] && [ -f "$patch_file" ] || exit 1
[ -z "$(ls -A "$shadow")" ] || exit 1
cp -a "$cached/." "$shadow/"
patch -d "$shadow" -p1 --fuzz=0 --forward --batch --dry-run <"$patch_file"
patch -d "$shadow" -p1 --fuzz=0 --forward --batch <"$patch_file"
cd "$shadow"
export PATH="${shadow%/build/*}/host/bin:$PATH"
export PYTHONHASHSEED=1 WAF_MAKE=1
timeout --signal=TERM --kill-after=5 240 python3 buildtools/bin/waf install \
    --targets=smbstatus,smbconf --destdir="$shadow/test-install" -j2
for output in bin/default/source3/utils/smbstatus.inst bin/default/source3/libsmbconf.inst.so; do
    [ -f "$output" ] && [ ! -L "$output" ] || exit 1
    if cmp -s "$cached/$output" "$output"; then
        echo 'Experiment retained an unchanged installed-form output' >&2
        exit 1
    fi
    sha256sum "$output"
done
