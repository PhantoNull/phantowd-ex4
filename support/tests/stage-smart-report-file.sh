#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Fixed test-only injection into a caller-owned disposable image.
set -eu
[ "$#" -eq 5 ] || exit 1
debugfs=$1 image=$2 input=$3 destination=$4 check=$5
case "$debugfs:$image:$input:$destination:$check" in
    *[!a-zA-Z0-9_./:-]*) exit 1 ;;
esac
for path in "$debugfs" "$image" "$input" "$check"; do
    case "$path" in /*) ;; *) exit 1 ;; esac
done
[ -f "$image" ] && [ ! -L "$image" ] || exit 1
[ -f "$input" ] && [ ! -L "$input" ] || exit 1
[ ! -e "$check" ] && [ ! -L "$check" ] || exit 1
case "$destination" in
    /usr/sbin/phantowd-smart-report-test|\
    /usr/sbin/phantowd-smart-collector-test|\
    /usr/sbin/phantowd-smart-report-init) ;;
    *) exit 1 ;;
esac
trap 'rm -f "$check"' EXIT
"$debugfs" -w -R "write $input $destination" "$image" >/dev/null 2>&1
"$debugfs" -w -R "set_inode_field $destination mode 0100755" "$image" >/dev/null 2>&1
"$debugfs" -w -R "set_inode_field $destination uid 0" "$image" >/dev/null 2>&1
"$debugfs" -w -R "set_inode_field $destination gid 0" "$image" >/dev/null 2>&1
# A zero debugfs status does not prove complete allocation or replacement.
"$debugfs" -R "dump $destination $check" "$image" >/dev/null 2>&1
[ -f "$check" ] && [ ! -L "$check" ] || exit 1
cmp -s "$input" "$check" || exit 1
metadata=$("$debugfs" -R "stat $destination" "$image" 2>/dev/null)
printf '%s\n' "$metadata" | grep -Eq '^Inode: [0-9]+ +Type: regular +Mode: +0755 +' || exit 1
printf '%s\n' "$metadata" | grep -Eq '^User: +0 +Group: +0 +' || exit 1
