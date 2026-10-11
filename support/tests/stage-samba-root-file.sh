#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Fixed test-only injection into a caller-owned disposable image.
set -eu
[ "$#" -eq 6 ] || exit 1
debugfs=$1 image=$2 input=$3 destination=$4 check=$5 mode=$6
case "$debugfs:$image:$input:$destination:$check" in
    *[!a-zA-Z0-9_./:-]*) exit 1 ;;
esac
for path in "$debugfs" "$image" "$input" "$check"; do
    case "$path" in /*) ;; *) exit 1 ;; esac
done
[ -f "$image" ] && [ ! -L "$image" ] || exit 1
[ -f "$input" ] && [ ! -L "$input" ] || exit 1
[ ! -e "$check" ] && [ ! -L "$check" ] || exit 1
case "$destination:$mode" in
    /usr/sbin/phantowd-samba-root-launcher:0100755|\
    /usr/sbin/phantowd-samba-charset-probe:0100755|\
    /usr/sbin/phantowd-runtime-bundle-probe:0100755|\
    /usr/sbin/phantowd-runtime-metadata-tests:0100755|\
    /usr/sbin/phantowd-runtime-owner-init:0100755|\
    /usr/sbin/phantowd-samba-owner-probe:0100755|\
    /usr/sbin/phantowd-samba-root-init:0100755|\
    /usr/lib/phantowd/qemu-samba-root.manifest:0100644) ;;
    *) exit 1 ;;
esac
trap 'rm -f "$check"' EXIT
"$debugfs" -w -R "write $input $destination" "$image" >/dev/null 2>&1
"$debugfs" -w -R "set_inode_field $destination mode $mode" "$image" >/dev/null 2>&1
"$debugfs" -w -R "set_inode_field $destination uid 0" "$image" >/dev/null 2>&1
"$debugfs" -w -R "set_inode_field $destination gid 0" "$image" >/dev/null 2>&1
# debugfs command success does not imply complete allocation or a write.
"$debugfs" -R "dump $destination $check" "$image" >/dev/null 2>&1
[ -f "$check" ] && [ ! -L "$check" ] || exit 1
cmp "$input" "$check" || exit 1
metadata=$("$debugfs" -R "stat $destination" "$image" 2>/dev/null)
mode_text=${mode#010}
printf '%s\n' "$metadata" | grep -Eq "^Inode: [0-9]+ +Type: regular +Mode: +$mode_text +" || exit 1
printf '%s\n' "$metadata" | grep -Eq '^User: +0 +Group: +0 +' || exit 1
