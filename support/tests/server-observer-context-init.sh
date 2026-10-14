#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 PhantoWD EX4 contributors
# Isolated synthetic context only; no smbd, NIC or physical disk.
set -eu
export PATH=/usr/sbin:/usr/bin:/sbin:/bin
mount -t proc proc /proc
mount -t sysfs sysfs /sys
awk '$2 == "/dev" && $3 == "devtmpfs" { found = 1 } END { exit !found }' /proc/mounts
mount -t tmpfs -o nosuid,nodev,size=32m,mode=0755 tmpfs /run
root=/run/phantowd-native-samba-root
state=/run/phantowd-native-samba-state
code=/run/phantowd-samba-code
mkdir -p "$root/etc" "$root/lib" "$root/usr" "$root/state" "$root/shares/readonly" "$root/shares/writable" "$state" "$code/lib" "$code/usr/sbin" /run/observer-readonly /run/observer-writable
mount -t tmpfs -o nosuid,nodev,noexec,size=64k,mode=0755 tmpfs "$root/etc"
mkdir "$root/etc/samba"
printf 'root:x:0:0:root:/:/bin/false\n' >"$root/etc/passwd"
printf 'root:x:0:\n' >"$root/etc/group"
printf 'passwd: files\ngroup: files\n' >"$root/etc/nsswitch.conf"
printf '[global]\nserver role = standalone server\n' >"$root/etc/samba/smb.conf"
chmod 0644 "$root/etc/passwd" "$root/etc/group" "$root/etc/nsswitch.conf"
chmod 0600 "$root/etc/samba/smb.conf"
mount -o remount,ro,nosuid,nodev,noexec "$root/etc"
mount -t tmpfs -o nosuid,nodev,noexec,size=64k,mode=0700 tmpfs "$state"
for role in private lock state cache pid rpc; do mkdir -m 0700 "$state/$role"; done
cp /usr/sbin/phantowd-server-observer-context-probe "$code/usr/sbin/"
chmod 0555 "$code/usr/sbin/phantowd-server-observer-context-probe"
mount --bind "$code" "$code"
mount -o remount,bind,ro,nosuid,nodev "$code"
mount -t ext4 -o ro,nosuid,nodev,noexec /dev/sdb /run/observer-readonly
mount -t ext4 -o rw,nosuid,nodev,noexec /dev/sdc /run/observer-writable
if /usr/sbin/phantowd-server-observer-context-test; then
    echo PHANTOWD_SERVER_OBSERVER_CONTEXT_GUEST_DONE
else
    echo PHANTOWD_SERVER_OBSERVER_CONTEXT_GUEST_FAILED
fi
sync
reboot -f
